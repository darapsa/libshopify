#include <fcntl.h>
#include <sys/stat.h>
#include "shopify.h"
#include "crypt.h"
#include "base64.h"
#include "regex.h"
#include "config.h"
#include "request.h"
#include "session.h"
#include "token.h"

#define AUTHORIZE_URL \
	"https://%s/oauth/authorize?client_id=%s&scope=%s&redirect_uri=%s%s"\
	"&state=%s"
#define AUTHORIZE_URL_LEN strlen(AUTHORIZE_URL) - strlen("%s") * 6

#define PAGE \
	"<!DOCTYPE html>\n"\
	"<html lang=\"en\">\n"\
	"\t<head>\n"\
	"\t\t<meta charset=\"utf-8\"/>\n"\
	"\t</head>\n"\
	"\t<body>\n"\
	"\t\t<script src=\"https://unpkg.com/@shopify/app-bridge@3\"/>\n"\
	"\t\t</script>\n"\
	"\t\t<script>\n"\
	"\t\t\tvar appBridge = window['app-bridge'];\n"\
	"\t\t\tvar redirect = appBridge.actions.Redirect;\n"\
	"\t\t\tredirect.create(appBridge.createApp({\n"\
	"\t\t\t\tapiKey: '%s',\n"\
	"\t\t\t\thost: '%s'\n"\
	"\t\t\t})).dispatch(redirect.Action.REMOTE, '%s');\n"\
	"\t\t</script>\n"\
	"\t</body>\n"\
	"</html>\n"
#define PAGE_LEN strlen(PAGE) - strlen("%s") * 3

#define FRAME "frame-ancestors https://%s https://admin.shopify.com;"
#define FRAME_LEN strlen(FRAME) - strlen("%s")

#define EMBEDDEDAPP_URL "https://%s/apps/%s/"
#define EMBEDDEDAPP_URL_LEN strlen(EMBEDDEDAPP_URL) - strlen("%s") * 2

extern inline void crypt_init();
extern inline bool crypt_maccmp(const char *, const char *, const char *);
extern inline void crypt_getnonce(char *, const size_t);
extern inline bool regex_match(const char *);
extern inline void base64_decode(unsigned char *, char **);
extern inline void config_getscopes(const char *, char **);
extern inline void request_init();
extern inline void request_token(const char *, const char *, const char *,
		const char *, char **);
extern inline void request_cleanup();
extern inline void token_parse(char *, struct session *);

void shopify_init()
{
	crypt_init();
	request_init();
	sessions = malloc(sizeof(struct session));
	sessions[0].shop = NULL;
}

static enum MHD_Result getparam(void *cls, enum MHD_ValueKind kind,
		const char *key, const char *val)
{
	if (kind == MHD_GET_ARGUMENT_KIND) {
		struct shopify_param **params = cls;
		int nparams = 0;
		while ((*params)[nparams].key)
			nparams++;
		*params = realloc(*params, sizeof(struct shopify_param)
				* (nparams + 2));
		(*params)[nparams].key = malloc(strlen(key) + 1);
		strcpy((*params)[nparams].key, key);
		(*params)[nparams].val = malloc(strlen(val) + 1);
		strcpy((*params)[nparams].val, val);
		(*params)[nparams + 1].key = NULL;
	}
	return MHD_YES;
}

static inline void clear(struct shopify_param params[])
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

bool shopify_valid(struct MHD_Connection *conn, const char *url,
		const char *redir_url, const char *secret_key,
		struct shopify_param *params[])
{
	(*params)[0].key = NULL;
	MHD_get_connection_values(conn, MHD_GET_ARGUMENT_KIND, getparam,
			params);
	int nparams = 0;
	while ((*params)[nparams].key)
		nparams++;
	if (!nparams)
		return false;
	qsort(*params, nparams, sizeof(struct shopify_param), keycmp);
	char *shop = NULL;
	struct shopify_param *param = bsearch(&(struct shopify_param)
			{ "shop" }, *params, nparams,
			sizeof(struct shopify_param), keycmp);
	if (param)
		shop = param->val;
	if (!shop || !regex_match(shop)) {
		clear(*params);
		return false;
	}
	param = NULL;
	char *query = NULL;
	for (int i = 0; i < nparams; i++) {
		const char *key = (*params)[i].key;
		const char *val = (*params)[i].val;
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
	param = bsearch(&(struct shopify_param){ "hmac" }, *params, nparams,
				sizeof(struct shopify_param), keycmp);
	if (param)
		hmac = param->val;
	if (!hmac || !crypt_maccmp(secret_key, query, hmac)) {
		clear(*params);
		free(query);
		return false;
	}
	free(query);
	if (strcmp(url, redir_url))
		return true;
	char *state = ((struct shopify_param *)bsearch(&(struct shopify_param)
				{ "state" }, *params, nparams,
				sizeof(struct shopify_param), keycmp))->val;
	int nsessions = 0;
	while (sessions[nsessions].shop)
		nsessions++;
	qsort(sessions, nsessions, sizeof(struct session), keycmp);
	struct session *session = bsearch(&(struct session){ shop }, sessions,
			nsessions, sizeof(struct session), keycmp);
	if (strcmp(state, session->nonce)) {
		clear(*params);
		return false;
	}
	return true;
}

static inline int redirect(const char *host, const char *id,
		struct MHD_Response **resp, struct MHD_Connection *conn)
{
	char url[EMBEDDEDAPP_URL_LEN + strlen(host) + strlen(id) + 1];
	sprintf(url, EMBEDDEDAPP_URL, host, id);
	*resp = MHD_create_response_from_buffer(0, "", MHD_RESPMEM_PERSISTENT);
	MHD_add_response_header(*resp, "Location", url);
	return MHD_queue_response(conn, MHD_HTTP_PERMANENT_REDIRECT, *resp);
}

enum MHD_Result shopify_respond(struct shopify_param params[], const char *url,
		const char *redir_url, const char *app_url, const char *app_id,
		const char *key, const char *secret_key, const char *toml_path,
		const char *html_path, struct MHD_Connection *conn,
		struct MHD_Response **resp)
{
	int nparams = 0;
	while (params[nparams].key)
		nparams++;
	char *shop = ((struct shopify_param *)bsearch(&(struct shopify_param)
				{ "shop" }, params, nparams,
				sizeof(struct shopify_param), keycmp))->val;
	const size_t shop_len = strlen(shop);
	char *host = ((struct shopify_param *)bsearch(&(struct shopify_param)
				{ "host" }, params, nparams,
				sizeof(struct shopify_param), keycmp))->val;
	struct shopify_param *param = bsearch(&(struct shopify_param)
			{ "embedded" }, params, nparams,
			sizeof(struct shopify_param), keycmp);
	bool embedded = param && !strcmp(param->val, "1");
	char *decoded_host;
	base64_decode((unsigned char *)host, &decoded_host);
	int nsessions = 0;
	while (sessions[nsessions].shop)
		nsessions++;
	qsort(sessions, nsessions, sizeof(struct session), keycmp);
	struct session *session = bsearch(&(struct session){ shop }, sessions,
			nsessions, sizeof(struct session), keycmp);
	const size_t key_len = strlen(key);
	char frame[FRAME_LEN + shop_len + 1];
	sprintf(frame, FRAME, shop);
	enum MHD_Result ret;
	if (!strcmp(url, redir_url)) {
		const char *code = ((struct shopify_param *)bsearch(
					&(struct shopify_param){ "code" },
					params, nparams,
					sizeof(struct shopify_param),
					keycmp))->val;
		char *token = NULL;
		request_token(decoded_host, key, secret_key, code, &token);
		token_parse(token, session);
		free(token);
		ret = redirect(decoded_host, app_id, resp, conn);
	} else if (session && session->token) {
		if (embedded) {
			int fd = open(html_path, O_RDONLY);
			struct stat sb;
			fstat(fd, &sb);
			char index[sb.st_size + 1];
			read(fd, index, sb.st_size);
			close(fd);
			*resp = MHD_create_response_from_buffer(sb.st_size,
					index, MHD_RESPMEM_MUST_COPY);
			MHD_add_response_header(*resp,
					"Content-Security-Policy", frame);
			ret = MHD_queue_response(conn, MHD_HTTP_OK, *resp);
		} else
			ret = redirect(decoded_host, app_id, resp, conn);
	} else {
		const size_t decoded_host_len = strlen(decoded_host);
		char *scopes = NULL;
		config_getscopes(toml_path, &scopes);
		const size_t scopes_len = strlen(scopes);
		static const size_t nonce_len = 64;
		char nonce[nonce_len + 1];
		crypt_getnonce(nonce, nonce_len);
		const size_t authorize_url_len = AUTHORIZE_URL_LEN
			+ decoded_host_len + key_len + scopes_len
			+ strlen(app_url) + strlen(redir_url) + nonce_len;
		char authorize_url[authorize_url_len + 1];
		sprintf(authorize_url, AUTHORIZE_URL, decoded_host, key, scopes,
				app_url, redir_url, nonce);
		free(scopes);
		sessions = realloc(sessions, sizeof(struct session)
				* (nsessions + 2));
		sessions[nsessions].shop = malloc(shop_len + 1);
		strcpy(sessions[nsessions].shop, shop);
		sessions[nsessions].nonce = malloc(nonce_len + 1);
		strcpy(sessions[nsessions].nonce, nonce);
		sessions[nsessions + 1].shop = NULL;
		if (embedded) {
			const size_t page_len = PAGE_LEN + key_len
				+ strlen(host) + authorize_url_len;
			char page[page_len + 1];
			sprintf(page, PAGE, key, host, authorize_url);
			*resp = MHD_create_response_from_buffer(page_len,
					page, MHD_RESPMEM_MUST_COPY);
			MHD_add_response_header(*resp,
					"Content-Security-Policy", frame);
			ret = MHD_queue_response(conn, MHD_HTTP_OK, *resp);
		} else {
			*resp = MHD_create_response_from_buffer(0, "",
					MHD_RESPMEM_PERSISTENT);
			MHD_add_response_header(*resp, "Location",
					authorize_url);
			ret = MHD_queue_response(conn,
					MHD_HTTP_TEMPORARY_REDIRECT, *resp);
		}
	}
	free(decoded_host);
	clear(params);
	return ret;
}

void shopify_cleanup()
{
	request_cleanup();
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
}
