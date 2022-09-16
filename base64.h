#include <gnutls/gnutls.h>

static inline void base64_decode(const char *host, char **decoded_host)
{
	gnutls_datum_t result;
	gnutls_base64_decode2(&(gnutls_datum_t){
			(unsigned char *)host,
			strlen(host)
		}, &result);
	*decoded_host = malloc(result.size + 1);
	strlcpy(*decoded_host, (const char *)result.data, result.size + 1);
	gnutls_free(result.data);
}
