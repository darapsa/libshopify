#include <stdbool.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <microhttpd.h>
#include "shopify.h"
#include "crypt.h"
#include "base64.h"
#include "regex.h"
#include "config.h"
#include "session.h"
#include "request.h"
#include "token.h"

#define AUTH_URL \
	"https://%s/oauth/authorize?client_id=%s&scope=%s&redirect_uri=%s%s"\
	"&state=%s"
#define AUTH_URL_LEN strlen(AUTH_URL) - strlen("%s") * 6

#define REDIR_PAGE \
	"<!DOCTYPE html>\n"\
	"<html lang=\"en\">\n"\
	"\t<head>\n"\
	"\t\t<meta charset=\"utf-8\"/>\n"\
	"\t</head>\n"\
	"\t<body>\n"\
	"\t\t<script src=\"https://unpkg.com/@shopify/app-bridge@3\">\n"\
	"\t\t</script>\n"\
	"\t\t<script>\n"\
	"\t\t\tvar AppBridge = window['app-bridge'];\n"\
	"\t\t\tvar Redirect = AppBridge.actions.Redirect;\n"\
	"\t\t\tRedirect.create(AppBridge.createApp({\n"\
	"\t\t\t\tapiKey: '%s',\n"\
	"\t\t\t\thost: '%s'\n"\
	"\t\t\t})).dispatch(Redirect.Action.REMOTE, '%s');\n"\
	"\t\t</script>\n"\
	"\t</body>\n"\
	"</html>\n"
#define REDIR_PAGE_LEN strlen(REDIR_PAGE) - strlen("%s") * 3

#define EMBEDDED_HEADER "frame-ancestors https://%s https://admin.shopify.com;"
#define EMBEDDED_HEADER_LEN strlen(EMBEDDED_HEADER) - strlen("%s")

#define EMBEDDED_URL "https://%s/apps/%s/"
#define EMBEDDED_URL_LEN strlen(EMBEDDED_URL) - strlen("%s") * 2

extern inline void crypt_init();
extern inline bool crypt_maccmp(const char *, const char *, const char *);
extern inline void crypt_getnonce(char [], const size_t);
extern inline bool regex_match(const char *);
extern inline void base64_decode(const char *, char **);
extern inline void config_getscopes(const char *, char **);
extern inline void request_init();
extern inline void request_token(const char *, const char *, const char *,
		const char *, char **);
extern inline void request_graphql(const char *, const struct shopify_session *,
		char **);
extern inline void request_cleanup();
extern inline void token_parse(const char *, struct shopify_session *);

struct parameter {
	char *key;
	char *val;
};

struct container {
	const char *key;
	const char *secret;
	const char *app_url;
	const char *redir_url;
	const char *app_id;
	const char *scope;
	const char *index;
	const struct shopify_api *apis;
	struct shopify_session *sessions;
};

static enum MHD_Result iterate(void *cls, enum MHD_ValueKind kind,
		const char *key, const char *val)
{
	switch (kind) {
		case MHD_GET_ARGUMENT_KIND:
			;
			struct parameter **params = cls;
			int nparams = 0;
			while ((*params)[nparams].key)
				nparams++;
			*params = realloc(*params, sizeof(struct parameter)
					* (nparams + 2));
			(*params)[nparams].key = malloc(strlen(key) + 1);
			strcpy((*params)[nparams].key, key);
			(*params)[nparams].val = malloc(strlen(val) + 1);
			strcpy((*params)[nparams].val, val);
			(*params)[nparams + 1].key = NULL;
			break;
		case MHD_HEADER_KIND:
			printf("%s: %s\n", key, val);
		default:
			break;
	}
	return MHD_YES;
}

static inline void clear(const struct parameter params[])
{
	int i = 0;
	while (params[i].key) {
		free(params[i].val);
		free(params[i++].key);
	}
}

static int keycmp(const void *struct1, const void *struct2)
{
	return strcmp(*(char **)struct1, *(char **)struct2);
}

static inline int redirect(const char *host, const char *id,
		struct MHD_Connection *con, struct MHD_Response **res)
{
	char url[EMBEDDED_URL_LEN + strlen(host) + strlen(id) + 1];
	sprintf(url, EMBEDDED_URL, host, id);
	*res = MHD_create_response_from_buffer(0, "", MHD_RESPMEM_PERSISTENT);
	MHD_add_response_header(*res, "Location", url);
	return MHD_queue_response(con, MHD_HTTP_PERMANENT_REDIRECT, *res);
}

static enum MHD_Result handle_request(void *cls, struct MHD_Connection *con,
		const char *url, const char *method, const char *version,
		const char *upload_data, size_t *upload_data_size,
		void **con_cls)
{
	struct parameter *params = *con_cls;
	if (!params) {
		params = malloc(sizeof(struct parameter));
		params[0].key = NULL;
		*con_cls = params;
		return MHD_YES;
	}
	MHD_get_connection_values(con, MHD_GET_ARGUMENT_KIND, iterate, &params);
	MHD_get_connection_values(con, MHD_HEADER_KIND, iterate, NULL);
	int nparams = 0;
	while (params[nparams].key)
		nparams++;
	if (!nparams) {
		free(params);
		return MHD_NO;
	}
	qsort(params, nparams, sizeof(struct parameter), keycmp);
	struct parameter *param = NULL;
	char *shop = NULL;
	if ((param = bsearch(&(struct parameter) { "shop" }, params, nparams,
					sizeof(struct parameter), keycmp)))
		shop = param->val;
	if (!shop || !regex_match(shop)) {
		clear(params);
		free(params);
		return MHD_NO;
	}
	char *query = NULL;
	for (int i = 0; i < nparams; i++) {
		const char *key = params[i].key;
		const char *val = params[i].val;
		if (strcmp(key, "hmac")) {
			size_t query_len = query ? strlen(query) : 0;
			bool ampersand_len = i != nparams - 1;
			query = realloc(query, query_len + strlen(key)
					+ strlen("=") + strlen(val)
					+ ampersand_len + 1);
			query[query_len] = '\0';
			sprintf(query, "%s%s=%s%s", query, key, val,
					ampersand_len ? "&" : "");
		}
	}
	char *hmac = NULL;
	if ((param = bsearch(&(struct parameter) { "hmac" }, params, nparams,
					sizeof(struct parameter), keycmp)))
		hmac = param->val;
	struct container *container = cls;
	const char *secret_key = container->secret;
	if (!hmac || !crypt_maccmp(secret_key, query, hmac)) {
		free(query);
		clear(params);
		free(params);
		return MHD_NO;
	}
	free(query);
	struct shopify_session *sessions = container->sessions;
	int nsessions = 0;
	while (sessions[nsessions].shop)
		nsessions++;
	qsort(sessions, nsessions, sizeof(struct shopify_session), keycmp);
	const char *redir_url = container->redir_url;
	if (!strcmp(url, redir_url)
			&& strcmp(((struct parameter *)bsearch(
						&(struct parameter){ "state" },
						params, nparams,
						sizeof(struct parameter),
						keycmp))->val,
				((struct shopify_session *)bsearch(
					&(struct shopify_session){ shop },
					sessions, nsessions,
					sizeof(struct shopify_session),
					keycmp))->nonce)) {
		clear(params);
		free(params);
		return MHD_NO;
	}
	const size_t shop_len = strlen(shop);
	char *host = ((struct parameter *)bsearch(&(struct parameter){ "host" },
				params, nparams, sizeof(struct parameter),
				keycmp))->val;
	const size_t host_len = strlen(host);
	param = bsearch(&(struct parameter){ "embedded" }, params, nparams,
			sizeof(struct parameter), keycmp);
	bool embedded = param && !strcmp(param->val, "1");
	char *dec_host;
	base64_decode(host, &dec_host);
	struct shopify_session *session = bsearch(&(struct shopify_session)
			{ shop }, sessions, nsessions,
			sizeof(struct shopify_session), keycmp);
	const char *key = container->key;
	const size_t key_len = strlen(key);
	const char *app_url = container->app_url;
	const size_t app_url_len = strlen(app_url);
	const char *app_id = container->app_id;
	char header[EMBEDDED_HEADER_LEN + shop_len + 1];
	sprintf(header, EMBEDDED_HEADER, shop);
	struct MHD_Response *res;
	enum MHD_Result ret = MHD_NO;
	if (!strcmp(url, redir_url)) {
		const char *code = ((struct parameter *)bsearch(
					&(struct parameter){ "code" }, params,
					nparams, sizeof(struct parameter),
					keycmp))->val;
		char *token = NULL;
		request_token(dec_host, key, secret_key, code, &token);
		token_parse(token, session);
		free(token);
		ret = redirect(dec_host, app_id, con, &res);
	} else if (session && session->token) {
		if (embedded) {
			if (!strcmp(url, "/") && !strcmp(method, "GET")) {
				int fd = open(container->index, O_RDONLY);
				struct stat sb;
				fstat(fd, &sb);
				char html[sb.st_size + 1];
				read(fd, html, sb.st_size);
				close(fd);
				const size_t index_len = sb.st_size
					- strlen("%s") * 4 + key_len + host_len
					+ app_url_len * 2;
				char index[index_len + 1];
				sprintf(index, html, key, host, app_url,
						app_url);
				res = MHD_create_response_from_buffer(index_len,
						index, MHD_RESPMEM_MUST_COPY);
				MHD_add_response_header(res,
						"Content-Security-Policy",
						header);
				ret = MHD_queue_response(con, MHD_HTTP_OK, res);
			} else {
				int i = 0;
				const struct shopify_api *api;
				while ((api = &(container->apis[i++])))
					if (!strcmp(url, api->url)
							&& !strcmp(method,
								api->method)) {
						char *json = NULL;
						api->cb(api->arg, session,
								json);
						res = MHD_create_response_from_buffer(
								strlen(json),
								json,
								MHD_RESPMEM_MUST_FREE);
						MHD_add_response_header(res,
								"Content-"\
								"Security-"\
								"Policy",
								header);
						MHD_add_response_header(res,
								"Content-"\
								"Type",
								"application/"\
								"json");
						ret = MHD_queue_response(con,
								MHD_HTTP_OK,
								res);
						break;
					}
			}
		} else
			ret = redirect(dec_host, app_id, con, &res);
	} else {
		const size_t dec_host_len = strlen(dec_host);
		char *scopes = NULL;
		config_getscopes(container->scope, &scopes);
		const size_t scopes_len = strlen(scopes);
		static const size_t nonce_len = 64;
		char nonce[nonce_len + 1];
		crypt_getnonce(nonce, nonce_len);
		const size_t auth_url_len = AUTH_URL_LEN + dec_host_len
			+ key_len + scopes_len + app_url_len
			+ strlen(redir_url) + nonce_len;
		char auth_url[auth_url_len + 1];
		sprintf(auth_url, AUTH_URL, dec_host, key, scopes, app_url,
				redir_url, nonce);
		free(scopes);
		sessions = realloc(sessions, sizeof(struct shopify_session)
				* (nsessions + 2));
		sessions[nsessions].shop = malloc(shop_len + 1);
		strcpy(sessions[nsessions].shop, shop);
		sessions[nsessions].nonce = malloc(nonce_len + 1);
		strcpy(sessions[nsessions].nonce, nonce);
		sessions[nsessions + 1].shop = NULL;
		container->sessions = sessions;
		if (embedded) {
			const size_t page_len = REDIR_PAGE_LEN + key_len
				+ host_len + auth_url_len;
			char page[page_len + 1];
			sprintf(page, REDIR_PAGE, key, host, auth_url);
			res = MHD_create_response_from_buffer(page_len,
					page, MHD_RESPMEM_MUST_COPY);
			MHD_add_response_header(res, "Content-Security-Policy",
					header);
			ret = MHD_queue_response(con, MHD_HTTP_OK, res);
		} else {
			res = MHD_create_response_from_buffer(0, "",
					MHD_RESPMEM_PERSISTENT);
			MHD_add_response_header(res, "Location", auth_url);
			ret = MHD_queue_response(con,
					MHD_HTTP_TEMPORARY_REDIRECT, res);
		}
	}
	free(dec_host);
	clear(params);
	free(params);
	return ret;
}

void shopify_app(const char *api_key, const char *api_secret_key,
		const char *app_url, const char *redir_url, const char *app_id,
		const char *scope, const char *index,
		const struct shopify_api apis[])
{
	crypt_init();
	request_init();
	struct shopify_session *sessions
		= malloc(sizeof(struct shopify_session));
	sessions[0].shop = NULL;
	struct MHD_Daemon *daemon
		= MHD_start_daemon(MHD_USE_INTERNAL_POLLING_THREAD, 3000, NULL,
				NULL, &handle_request, &(struct container){
				api_key,
				api_secret_key,
				app_url,
				redir_url,
				app_id,
				scope,
				index,
				apis,
				sessions
			}, MHD_OPTION_END);
	getchar();
	MHD_stop_daemon(daemon);
	int i = 0;
	while (sessions[i].shop) {
		if (sessions[i].scope)
			free(sessions[i].scope);
		if (sessions[i].token)
			free(sessions[i].token);
		free(sessions[i].nonce);
		free(sessions[i++].shop);
	}
	free(sessions);
	request_cleanup();
}

void shopify_graphql(const char *query, const struct shopify_session *session,
		char **json)
{
	request_graphql(query, session, json);
}
