#include "request.h"
#include "shopify.h"

extern inline void request_gettoken(const char *, const char *, const char *,
		const char *, char **);

void shopify_graphql(const char *query, const struct shopify_session *session,
		char **json)
{
	CURL *curl = curl_easy_init();
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, append);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, json);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, query);

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
