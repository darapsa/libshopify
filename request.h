#include <curl/curl.h>

#define TOKEN_URL "https://%s/oauth/access_token"
#define TOKEN_URL_LEN strlen(TOKEN_URL) - strlen("%s")

#define TOKEN_POST "client_id=%s&client_secret=%s&code=%s"
#define TOKEN_POST_LEN strlen(TOKEN_POST) - strlen("%s") * 3

#define TOKEN_HEADER "X-Shopify-Access-Token: %s"
#define TOKEN_HEADER_LEN strlen(TOKEN_HEADER) - strlen("%s")

#define GRAPHQL_URL "https://%s/admin/api/2022-07/graphql.json"
#define GRAPHQL_URL_LEN strlen(GRAPHQL_URL) - strlen("%s")

static inline void request_init()
{
	curl_global_init(CURL_GLOBAL_DEFAULT);
}

static size_t append(char *data, size_t size, size_t nmemb, char **json)
{
	size_t realsize = size * nmemb;
	size_t json_len = *json ? strlen(*json) : 0;
	*json = realloc(*json, json_len + realsize + 1);
	strlcpy(&(*json)[json_len], data, realsize + 1);
	return realsize;
}

static inline void request_token(const char *host, const char *key,
		const char *secret_key, const char *code, char **json)
{
	CURL *curl = curl_easy_init();
	char url[TOKEN_URL_LEN + strlen(host) + 1];
	sprintf(url, TOKEN_URL, host);
	curl_easy_setopt(curl, CURLOPT_URL, url);
	char post[TOKEN_POST_LEN + strlen(key) + strlen(secret_key)
		+ strlen(code) + 1];
	sprintf(post, TOKEN_POST, key, secret_key, code);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, append);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, json);
#ifdef DEBUG
	curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
#endif
	curl_easy_perform(curl);
	curl_easy_cleanup(curl);
}

static inline void request_graphql(const char *query,
		const struct shopify_session *session, char **json)
{
	CURL *curl = curl_easy_init();
	char url[GRAPHQL_URL_LEN + strlen(session->shop) + 1];
	sprintf(url, GRAPHQL_URL, session->shop);
	curl_easy_setopt(curl, CURLOPT_URL, url);
	struct curl_slist *list = NULL;
	curl_slist_append(list, "Content-Type: application/json");
	char header[TOKEN_HEADER_LEN + strlen(session->token) + 1];
	sprintf(header, TOKEN_HEADER, session->token);
	curl_slist_append(list, header);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, query);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, append);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, json);
#ifdef DEBUG
	curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
#endif
	curl_easy_perform(curl);
	curl_slist_free_all(list);
	curl_easy_cleanup(curl);
}

static inline void request_cleanup()
{
	curl_global_cleanup();
}
