#ifndef SHOPIFY_H
#define SHOPIFY_H

struct shopify_session {
	char *shop;
	char *nonce;
	char *access_token;
	char *scopes;
};

struct shopify_api {
	char *url;
	char *method;
	void (*cb)(const char *, const struct shopify_session *, char **);
	void *arg;
};

struct shopify_carrierservice {
	char *url;
	char *(*rates)(const char *, const char *, long,
			const struct shopify_session *);
};

#ifdef __cplusplus
extern "C" {
#endif

void shopify_app(const char *api_key, const char *api_secret_key,
		const char *app_url, const char *redir_url, const char *app_id,
		const char *scopes, char *(*html)(const char *host),
		const char *js_dir, const struct shopify_api apis[],
		const struct shopify_carrierservice carrierservices[]);
void shopify_graphql(const char *query, const struct shopify_session *session,
		char **json);

#ifdef __cplusplus
}
#endif

#endif
