#ifndef SHOPIFY_H
#define SHOPIFY_H

struct shopify_api {
	char *url;
	char *method;
	void (*cb)();
	void *arg;
};

struct shopify_session;

#ifdef __cplusplus
extern "C" {
#endif

void shopify_app(const char *api_key, const char *api_secret_key,
		const char *app_url, const char *redir_url, const char *app_id,
		const char *scope, const char *index,
		const struct shopify_api apis[]);
void shopify_graphql(const char *query, const struct shopify_session *session,
		char **json);

#ifdef __cplusplus
}
#endif

#endif
