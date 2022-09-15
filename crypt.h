#include <gcrypt.h>

static inline void crypt_init()
{
	gcry_check_version("1.9.4");
}

static inline bool crypt_maccmp(const char *key, const char *query,
		const char *hmac)
{
	gcry_mac_hd_t hd;
	gcry_mac_open(&hd, GCRY_MAC_HMAC_SHA256, GCRY_MAC_FLAG_SECURE, NULL);
	gcry_mac_setkey(hd, key, strlen(key));
	gcry_mac_write(hd, query, strlen(query));
	static size_t hmacsha256_len = 32;
	unsigned char hmacsha256[hmacsha256_len + 1];
	gcry_mac_read(hd, hmacsha256, &hmacsha256_len);
	gcry_mac_close(hd);
	char hmacsha256_str[hmacsha256_len * 2 + 1];
	hmacsha256_str[0] ='\0';
	for (int i = 0; i < hmacsha256_len; i++)
		sprintf(hmacsha256_str, "%s%02x", hmacsha256_str,
				hmacsha256[i]);
	return !strcmp(hmac, hmacsha256_str);
}

static inline void crypt_getnonce(char buf[], const size_t buf_len)
{
	buf[0] = '\0';
	const size_t nonce_len = buf_len / 2;
	unsigned char nonce[nonce_len + 1];
	gcry_create_nonce(nonce, nonce_len);
	for (int i = 0; i < nonce_len; i++)
		sprintf(buf, "%s%02x", buf, nonce[i]);
}
