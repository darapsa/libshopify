#include <curl/curl.h>

#define TOKEN_URL "https://%s/oauth/access_token"
#define TOKEN_URL_LEN strlen(TOKEN_URL) - strlen("%s")

#define TOKEN_POST "client_id=%s&client_secret=%s&code=%s"
#define TOKEN_POST_LEN strlen(TOKEN_POST) - strlen("%s") * 3

static inline void request_init()
{
	curl_global_init(CURL_GLOBAL_DEFAULT);
}

static size_t append(char *data, size_t size, size_t nmemb, char **tok)
{
	size_t realsize = size * nmemb;
	size_t tok_len = *tok ? strlen(*tok) : 0;
	*tok = realloc(*tok, tok_len + realsize + 1);
	strlcpy(&(*tok)[tok_len], data, realsize + 1);
	return realsize;
}

static inline void request_token(const char *host, const char *key,
		const char *secret_key, const char *code, char **tok)
{
	CURL *curl = curl_easy_init();
	char url[TOKEN_URL_LEN + strlen(host) + 1];
	sprintf(url, TOKEN_URL, host);
	curl_easy_setopt(curl, CURLOPT_URL, url);
	char post[TOKEN_POST_LEN + strlen(key) + strlen(secret_key)
		+ strlen(code) + 1];
	sprintf(post, TOKEN_POST, key, secret_key, code);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, tok);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, append);
#ifdef DEBUG
	curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
#endif
	curl_easy_perform(curl);
	curl_easy_cleanup(curl);
}

static inline void request_cleanup()
{
	curl_global_cleanup();
}