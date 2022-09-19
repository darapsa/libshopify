#include <gnutls/gnutls.h>

static inline void base64_getdecoded(const char *host, char **dec_host)
{
	gnutls_datum_t result;
	gnutls_base64_decode2(&(gnutls_datum_t){
			(unsigned char *)host,
			strlen(host)
		}, &result);
	*dec_host = malloc(result.size + 1);
	strlcpy(*dec_host, (const char *)result.data, result.size + 1);
	gnutls_free(result.data);
}
