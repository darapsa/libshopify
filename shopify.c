#include <fcntl.h>
#include <sys/stat.h>
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#include <gcrypt.h>
#include <gnutls/gnutls.h>
#include <toml.h>
#include <curl/curl.h>
#include <json.h>
#include <l8w8jwt/decode.h>
#include <microhttpd.h>
#include "shopify.h"

struct parameter {
	char *key;
	char *val;
};

struct container {
	const char *api_key;
	const char *api_secret_key;
	const char *app_url;
	const char *redir_url;
	const char *app_id;
	const char *scopes;
	char *(*html)(const char *);
	const char *js_dir;
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
			;
			char ***array = cls;
			if (!strcmp(key, "Authorization")) {
				static const char *schema = "Bearer ";
				const size_t schema_len = strlen(schema);
				const int token_len = strlen(val) - schema_len;
				if (token_len < 0)
					break;
				*array[0] = malloc(token_len + 1);
				strcpy(*array[0], &val[schema_len]);
			} else if (!strcmp(key, "Referer")) {
				*array[1] = malloc(strlen(val) + 1);
				strcpy(*array[1], val);
			}
			break;
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

static int compare(const void *struct1, const void *struct2)
{
	return strcmp(*(char **)struct1, *(char **)struct2);
}

static inline _Bool match(const char *shop)
{
	pcre2_code *re = pcre2_compile((PCRE2_SPTR)
			"^[a-zA-Z0-9][a-zA-Z0-9\\-]*\\.myshopify\\.com",
			PCRE2_ZERO_TERMINATED, 0, &(int){ 0 },
			&(PCRE2_SIZE){ 0 }, NULL);
	pcre2_match_data *match_data
		= pcre2_match_data_create_from_pattern(re, NULL);
	int rc = pcre2_match(re, (PCRE2_SPTR)shop, strlen(shop), 0, 0,
			match_data, NULL);
	pcre2_match_data_free(match_data);
	pcre2_code_free(re);
	return rc >= 0;
}

static size_t append(char *data, size_t size, size_t nmemb, char **res)
{
	size_t realsize = size * nmemb;
	size_t res_len = *res ? strlen(*res) : 0;
	*res = realloc(*res, res_len + realsize + 1);
	strlcpy(&(*res)[res_len], data, realsize + 1);
	return realsize;
}

static inline int redirect(const char *host, const char *id,
		struct MHD_Connection *con, struct MHD_Response **res)
{
	static const char *tmpl = "https://%s/apps/%s/";
	char url[strlen(tmpl) - strlen("%s") * 2 + strlen(host) + strlen(id)
		+ 1];
	sprintf(url, tmpl, host, id);
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
	struct container *container = cls;
	struct MHD_Response *res = NULL;
	enum MHD_Result ret = MHD_NO;

	char *dot = strrchr(url, '.');
	if (dot && !strcmp(method, "GET")
			&& (!strcmp(dot, ".js") || !strcmp(dot, ".wasm")
				|| !strcmp(dot, ".data"))) {
		char path[strlen(container->js_dir) + strlen(url) + 1];
		sprintf(path, "%s%s", container->js_dir, url);
		int fd = open(path, O_RDONLY);
		if (fd == -1) {
			close(fd);
			static char *notfound = "Not Found";
			res = MHD_create_response_from_buffer(strlen(notfound),
					notfound, MHD_RESPMEM_PERSISTENT);
			ret = MHD_queue_response(con, MHD_HTTP_NOT_FOUND, res);
		} else {
			struct stat sb;
			fstat(fd, &sb);
			char file[sb.st_size + 1];
			read(fd, file, sb.st_size);
			close(fd);
			res = MHD_create_response_from_buffer(sb.st_size, file,
					MHD_RESPMEM_MUST_COPY);
			static const char *js_type = "application/javascript";
			static const char *wasm_type = "application/wasm";
			static const char *data_type = "text/html";
			const char *type = NULL;
			if (!strcmp(dot, ".js"))
				type = js_type;
			else if (!strcmp(dot, ".wasm"))
				type = wasm_type;
			else if (!strcmp(dot, ".data"))
				type = data_type;
			MHD_add_response_header(res, "Content-Type", type);
			ret = MHD_queue_response(con, MHD_HTTP_OK, res);
		}
		return ret;
	}

	MHD_get_connection_values(con, MHD_GET_ARGUMENT_KIND, iterate, &params);
	const char *api_key = container->api_key;
	const size_t api_key_len = strlen(api_key);
	const char *api_secret_key = container->api_secret_key;
	const char *app_url = container->app_url;
	const size_t app_url_len = strlen(app_url);
	const char *redir_url = container->redir_url;
	struct shopify_session *sessions = container->sessions;
	int nsessions = 0;
	while (sessions[nsessions].shop)
		nsessions++;
	qsort(sessions, nsessions, sizeof(struct shopify_session), compare);
	char *shop = NULL;
	size_t shop_len = 0;
	char *session_token = NULL;
	struct parameter *param = NULL;
	int nparams = 0;
	while (params[nparams].key)
		nparams++;
	if (nparams) {
		qsort(params, nparams, sizeof(struct parameter), compare);
		if ((param = bsearch(&(struct parameter){ "shop" }, params,
						nparams,
						sizeof(struct parameter),
						compare)))
			shop = param->val;
		if (!shop || !match(shop)) {
			clear(params);
			free(params);
			return MHD_NO;
		}
		shop_len = strlen(shop);
		char *query = NULL;
		for (int i = 0; i < nparams; i++) {
			const char *key = params[i].key;
			const char *val = params[i].val;
			if (strcmp(key, "hmac")) {
				size_t query_len = query ? strlen(query) : 0;
				_Bool ampersand_len = i != nparams - 1;
				query = realloc(query, query_len + strlen(key)
						+ strlen("=") + strlen(val)
						+ ampersand_len + 1);
				query[query_len] = '\0';
				sprintf(query, "%s%s=%s%s", query, key, val,
						ampersand_len ? "&" : "");
			}
		}
		char *hmac = NULL;
		if ((param = bsearch(&(struct parameter){ "hmac" }, params,
						nparams,
						sizeof(struct parameter),
						compare)))
			hmac = param->val;
		if (!hmac) {
			free(query);
			clear(params);
			free(params);
			return MHD_NO;
		}

		gcry_mac_hd_t hd;
		gcry_mac_open(&hd, GCRY_MAC_HMAC_SHA256, GCRY_MAC_FLAG_SECURE,
				NULL);
		gcry_mac_setkey(hd, api_secret_key, strlen(api_secret_key));
		gcry_mac_write(hd, query, strlen(query));
		static size_t hmacsha256_len = 32;
		unsigned char hmacsha256[hmacsha256_len];
		gcry_mac_read(hd, hmacsha256, &hmacsha256_len);
		gcry_mac_close(hd);
		char hmacsha256_str[hmacsha256_len * 2 + 1];
		hmacsha256_str[0] ='\0';
		for (int i = 0; i < hmacsha256_len; i++)
			sprintf(hmacsha256_str, "%s%02x", hmacsha256_str,
					hmacsha256[i]);
		if (strcmp(hmac, hmacsha256_str)) {
			free(query);
			clear(params);
			free(params);
			return MHD_NO;
		}

		free(query);
		if (!strcmp(url, redir_url)
				&& strcmp(((struct parameter *)bsearch(
							&(struct parameter)
							{ "state" }, params,
							nparams,
							sizeof(struct parameter),
							compare))->val,
					((struct shopify_session *)bsearch(
						&(struct shopify_session)
						{ shop }, sessions, nsessions,
						sizeof(struct shopify_session),
						compare))->nonce)) {
			clear(params);
			free(params);
			return MHD_NO;
		}
	} else {
		free(params);
		params = NULL;

		char *referer = NULL;
		MHD_get_connection_values(con, MHD_HEADER_KIND, iterate,
				(char **[]){ &session_token, &referer });
 		if (!session_token || !referer
				|| strncmp(referer, app_url, app_url_len)
				|| referer[app_url_len] != '?'
				|| !&referer[app_url_len + 1]) {
			if (session_token)
				free(session_token);
			if (referer)
				free(referer);
			return MHD_NO;
		}

		referer = &referer[app_url_len + 1];
		char *tofree = referer;
		char *pair = NULL;
		static const char *key = "shop=";
		const size_t key_len = strlen(key);
		while ((pair = strsep(&referer, "&")))
			if (!strncmp(pair, key, key_len))
				break;
		if (!pair || !&pair[key_len]) {
			free(session_token);
			free(tofree);
			return MHD_NO;
		}

		pair = &pair[key_len];
		shop_len = strchrnul(pair, '&') - pair;
		shop = malloc(shop_len + 1);
		strlcpy(shop, pair, shop_len + 1);
		free(tofree);
		if (!match(shop)) {
			free(session_token);
			free(shop);
			return MHD_NO;
		}

		struct l8w8jwt_decoding_params params;
		l8w8jwt_decoding_params_init(&params);
		params.alg = L8W8JWT_ALG_HS256;
		params.jwt = (char *)session_token;
		params.jwt_length = strlen(session_token);
		params.verification_key = (unsigned char *)api_secret_key;
		params.verification_key_length = strlen(api_secret_key);
		params.validate_exp = 1;
		params.validate_nbf = 1;
		params.validate_aud = (char *)api_key;
		enum l8w8jwt_validation_result validation;
		struct l8w8jwt_claim *claims;
		size_t claims_len;
		int decode = l8w8jwt_decode(&params, &validation, &claims,
				&claims_len);
		if (validation != L8W8JWT_NBF_FAILURE)
			printf("JWT payload nbf is invalid.\n");
		struct l8w8jwt_claim *dest
			= l8w8jwt_get_claim(claims, claims_len, "dest", 4);
		_Bool iss_valid = !strncmp( l8w8jwt_get_claim(claims,
					claims_len, "iss", 3)->value,
				dest->value, dest->value_length);
		printf("JWT payload sub: %s\n", l8w8jwt_get_claim(claims,
					claims_len, "sub", 3)->value);
		l8w8jwt_free_claims(claims, claims_len);
		if (decode != L8W8JWT_SUCCESS
				|| validation != L8W8JWT_VALID
				&& validation != L8W8JWT_NBF_FAILURE
				|| !iss_valid) {
			free(session_token);
			free(shop);
			return MHD_NO;
		}
	}

	char *host = NULL;
	size_t host_len = 0;
	_Bool embedded = 0;
	char *dec_host = NULL;
	size_t dec_host_len = 0;
	if (params) {
		host = ((struct parameter *)bsearch(&(struct parameter)
					{ "host" }, params, nparams,
					sizeof(struct parameter), compare))->val;
		host_len = strlen(host);
		param = bsearch(&(struct parameter){ "embedded" }, params,
				nparams, sizeof(struct parameter), compare);
		embedded = param && !strcmp(param->val, "1");

		gnutls_datum_t result;
		gnutls_base64_decode2(&(gnutls_datum_t){
				(unsigned char *)host,
				host_len
			}, &result);
		dec_host_len = result.size;
		dec_host = malloc(dec_host_len + 1);
		strlcpy(dec_host, (const char *)result.data, dec_host_len + 1);
		gnutls_free(result.data);
	}

	static const char *header_tmpl
		= "frame-ancestors https://%s https://admin.shopify.com;";
	char header[strlen(header_tmpl) - strlen("%s") + shop_len + 1];
	sprintf(header, header_tmpl, shop);
	struct shopify_session *session = bsearch(&(struct shopify_session)
			{ shop }, sessions, nsessions,
			sizeof(struct shopify_session), compare);
	const char *app_id = container->app_id;

	if (!strcmp(url, redir_url)) {
		const char *code = ((struct parameter *)bsearch(
					&(struct parameter){ "code" }, params,
					nparams, sizeof(struct parameter),
					compare))->val;

		CURL *curl = curl_easy_init();
		char *json = NULL;
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &json);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, append);
		static const char *url_tmpl = "https://%s/oauth/access_token";
		char url[strlen(url_tmpl) - strlen("%s") + dec_host_len + 1];
		sprintf(url, url_tmpl, dec_host);
		curl_easy_setopt(curl, CURLOPT_URL, url);
		static const char *post_tmpl
			= "client_id=%s&client_secret=%s&code=%s";
		char post[strlen(post_tmpl) - strlen("%s") * 3 + strlen(api_key)
			+ strlen(api_secret_key) + strlen(code) + 1];
		sprintf(post, post_tmpl, api_key, api_secret_key, code);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post);
		curl_easy_perform(curl);
		curl_easy_cleanup(curl);

		json_tokener *tokener = json_tokener_new();
		json_object *obj = json_tokener_parse_ex(tokener, json,
				strlen(json));
		struct json_object_iterator iter = json_object_iter_begin(obj);
		struct json_object_iterator iter_end
			= json_object_iter_end(obj);
		while (!json_object_iter_equal(&iter, &iter_end)) {
			json_object *val = json_object_iter_peek_value(&iter);
			if (!strcmp(json_object_iter_peek_name(&iter),
						"access_token")) {
				const char *str = json_object_get_string(val);
				session->access_token = malloc(strlen(str) + 1);
				strcpy(session->access_token, str);
			} else if (!strcmp(json_object_iter_peek_name(&iter),
						"scope")) {
				const char *str = json_object_get_string(val);
				session->scopes = malloc(strlen(str) + 1);
				strcpy(session->scopes, str);
			}
			json_object_iter_next(&iter);
		}
		json_tokener_free(tokener);
		free(json);

		ret = redirect(dec_host, app_id, con, &res);
	} else if (session_token) {
		free(session_token);
		free(shop);
		int i = 0;
		const struct shopify_api *api;
		while ((api = &(container->apis[i++])))
			if (!strcmp(url, api->url)
					&& !strcmp(method, api->method)) {
				char *json = NULL;
				if (!strcmp(method, "POST")
						&& upload_data_size) {
					api->cb(upload_data, session, &json);
					*upload_data_size = 0;
				} else
					api->cb(api->arg, session, &json);
				res = MHD_create_response_from_buffer(
						strlen(json), json,
						MHD_RESPMEM_MUST_FREE);
				MHD_add_response_header(res,
						"Content-Security-Policy",
						header);
				MHD_add_response_header(res, "Content-Type",
						"application/json");
				ret = MHD_queue_response(con, MHD_HTTP_OK, res);
				break;
			}
	} else if (session && session->access_token) {
		if (embedded) {
			char *html = container->html(host);
			res = MHD_create_response_from_buffer(strlen(html),
					html, MHD_RESPMEM_MUST_FREE);
			MHD_add_response_header(res, "Content-Security-Policy",
					header);
			ret = MHD_queue_response(con, MHD_HTTP_OK, res);
		} else
			ret = redirect(dec_host, app_id, con, &res);
	} else {
		FILE *fp = fopen(container->scopes, "r");
		toml_table_t* toml = toml_parse_file(fp, NULL, 0);
		fclose(fp);
		char *scopes = toml_string_in(toml, "scopes").u.s;
		toml_free(toml);

		static const size_t nonce_len = 64;
		char nonce[nonce_len + 1];
		nonce[0] = '\0';
		const size_t hex_len = nonce_len / 2;
		unsigned char hex[hex_len];
		gcry_create_nonce(hex, hex_len);
		for (int i = 0; i < hex_len; i++)
			sprintf(nonce, "%s%02x", nonce, hex[i]);

		static const char *tmpl = "https://%s/oauth/authorize"
			"?client_id=%s&scope=%s&redirect_uri=%s%s&state=%s";
		const size_t auth_url_len = strlen(tmpl) - strlen("%s") * 6
			+ dec_host_len + api_key_len + strlen(scopes)
			+ app_url_len + strlen(redir_url) + nonce_len;
		char auth_url[auth_url_len + 1];
		sprintf(auth_url, tmpl, dec_host, api_key, scopes, app_url,
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
			static const char *tmpl =
				"<!DOCTYPE html>\n"
				"<html lang=\"en\">\n"
				"\t<head>\n"
				"\t\t<meta charset=\"utf-8\"/>\n"
				"\t</head>\n"
				"\t<body>\n"
				"\t\t<script src="
				"\"https://unpkg.com/@shopify/app-bridge@3\">\n"
				"\t\t</script>\n"
				"\t\t<script>\n"
				"\t\t\tvar AppBridge = window['app-bridge'];\n"
				"\t\t\tvar Redirect = "
				"AppBridge.actions.Redirect;\n"
				"\t\t\tRedirect.create(AppBridge.createApp({\n"
				"\t\t\t\tapiKey: '%s',\n"
				"\t\t\t\thost: '%s'\n"
				"\t\t\t})).dispatch(Redirect.Action.REMOTE, "
				"'%s');\n"
				"\t\t</script>\n"
				"\t</body>\n"
				"</html>\n";
			const size_t page_len = strlen(tmpl) - strlen("%s") * 3
				+ api_key_len + host_len + auth_url_len;
			char page[page_len + 1];
			sprintf(page, tmpl, api_key, host, auth_url);
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
	if (params) {
		free(dec_host);
		clear(params);
		free(params);
	}
	return ret;
}

void shopify_app(const char *api_key, const char *api_secret_key,
		const char *app_url, const char *redir_url, const char *app_id,
		const char *scopes, char *(*html)(const char *host),
		const char *js_dir, const struct shopify_api apis[])
{
	gcry_check_version("1.9.4");
	curl_global_init(CURL_GLOBAL_DEFAULT);
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
				scopes,
				html,
				js_dir,
				apis,
				sessions
			}, MHD_OPTION_END);
	getchar();
	MHD_stop_daemon(daemon);
	int i = 0;
	while (sessions[i].shop) {
		if (sessions[i].scopes)
			free(sessions[i].scopes);
		if (sessions[i].access_token)
			free(sessions[i].access_token);
		free(sessions[i].nonce);
		free(sessions[i++].shop);
	}
	free(sessions);
	curl_global_cleanup();
}

void shopify_graphql(const char *query, const struct shopify_session *session,
		char **json)
{
	CURL *curl = curl_easy_init();
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, query);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, json);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, append);

	static const char *url_tmpl
		= "https://%s/admin/api/2022-07/graphql.json";
	char url[strlen(url_tmpl) - strlen("%s") + strlen(session->shop) + 1];
	sprintf(url, url_tmpl, session->shop);
	curl_easy_setopt(curl, CURLOPT_URL, url);

	static const char *hdr_tmpl = "X-Shopify-Access-Token: %s";
	char header[strlen(hdr_tmpl) - strlen("%s")
		+ strlen(session->access_token) + 1];
	sprintf(header, hdr_tmpl, session->access_token);

	struct curl_slist *list = NULL;
	list = curl_slist_append(list, header);
	list = curl_slist_append(list, "Content-Type: application/graphql");
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list);

	curl_easy_perform(curl);
	curl_slist_free_all(list);
	curl_easy_cleanup(curl);
}
