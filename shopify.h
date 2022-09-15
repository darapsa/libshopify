#ifndef SHOPIFY_H
#define SHOPIFY_H

#include <stdbool.h>
#include <microhttpd.h>

struct shopify_param {
	char *key;
	char *val;
};

#ifdef __cplusplus
extern "C" {
#endif

void shopify_init();
bool shopify_valid(struct MHD_Connection *conn, const char *url,
		const char *redir_url, const char *key,
		struct shopify_param *params[]);
enum MHD_Result shopify_respond(const struct shopify_param params[],
		const char *url, const char *redir_url, const char *app_url,
		const char *app_id, const char *key, const char *secret_key,
		const char *toml_path, const char *html_path,
		struct MHD_Connection *conn, struct MHD_Response **resp);
void shopify_cleanup();

#ifdef __cplusplus
}
#endif

#endif
