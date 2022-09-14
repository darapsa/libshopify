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
	size_t hmac_sha256_len = 32;
	unsigned char hmac_sha256[hmac_sha256_len + 1];
	gcry_mac_read(hd, hmac_sha256, &hmac_sha256_len);
	gcry_mac_close(hd);
	char hmac_sha256_str[65] = { [0] = '\0' };
	for (int i = 0; i < hmac_sha256_len; i++)
		sprintf(hmac_sha256_str, "%s%02x", hmac_sha256_str,
				hmac_sha256[i]);
	return !strcmp(hmac, hmac_sha256_str);
}

static inline void crypt_getnonce(char *string, const size_t string_len)
{
	string[0] = '\0';
	const size_t nonce_len = string_len / 2;
	unsigned char nonce[nonce_len + 1];
	gcry_create_nonce(nonce, nonce_len);
	for (int i = 0; i < nonce_len; i++)
		sprintf(string, "%s%02x", string, nonce[i]);
}