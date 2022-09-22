#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

static size_t append(char *data, size_t size, size_t nmemb, char **res)
{
	size_t realsize = size * nmemb;
	size_t res_len = *res ? strlen(*res) : 0;
	*res = realloc(*res, res_len + realsize + 1);
	strlcpy(&(*res)[res_len], data, realsize + 1);
	return realsize;
}

static inline void request_gettoken(const char *host, const char *key,
		const char *secret_key, const char *code, char **json)
{
	CURL *curl = curl_easy_init();
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, append);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, json);

	static const char *url_tmpl = "https://%s/oauth/access_token";
	char url[strlen(url_tmpl) - strlen("%s") + strlen(host) + 1];
	sprintf(url, url_tmpl, host);
	curl_easy_setopt(curl, CURLOPT_URL, url);

	static const char *post_tmpl = "client_id=%s&client_secret=%s&code=%s";
	char post[strlen(post_tmpl) - strlen("%s") * 3 + strlen(key)
		+ strlen(secret_key) + strlen(code) + 1];
	sprintf(post, post_tmpl, key, secret_key, code);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post);

	curl_easy_perform(curl);
	curl_easy_cleanup(curl);
}
