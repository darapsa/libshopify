#include "request.h"
#include "shopify.h"

#define GRAPHQL_URL "https://%s/admin/api/2022-07/graphql.json"
#define GRAPHQL_URL_LEN strlen(GRAPHQL_URL) - strlen("%s")

extern inline void request_gettoken(const char *, const char *, const char *,
		const char *, char **);

void shopify_graphql(const char *query, const struct shopify_session *session,
		char **json)
{
	CURL *curl = curl_easy_init();
	char url[GRAPHQL_URL_LEN + strlen(session->shop) + 1];
	sprintf(url, GRAPHQL_URL, session->shop);
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, query);
	struct curl_slist *list = NULL;
	char header[TOKEN_HEADER_LEN + strlen(session->access_token) + 1];
	sprintf(header, TOKEN_HEADER, session->access_token);
	list = curl_slist_append(list, header);
	list = curl_slist_append(list, "Content-Type: application/graphql");
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, append);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, json);
	curl_easy_perform(curl);
	curl_slist_free_all(list);
	curl_easy_cleanup(curl);
}
