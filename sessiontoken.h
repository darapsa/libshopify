#include <jwt.h>

static inline bool sessiontoken_isvalid(const char *token, const char *secret)
{
	const size_t key_len = strlen(secret) / 2;
	unsigned char key[key_len];
	for (size_t i = 0; i < key_len; i++) {
		char hex[3] = { [2] = '\0' };
		strncpy(hex, &secret[i], 2);
		key[i] = strtol(hex, NULL, 16);
	}
	jwt_t *jwt = NULL;
	jwt_decode(&jwt, token, key, key_len);
	printf("exp: %s\n", jwt_get_grant(jwt, "exp"));
	printf("nbf: %s\n", jwt_get_grant(jwt, "nbf"));
	printf("iss: %s\n", jwt_get_grant(jwt, "iss"));
	printf("dest: %s\n", jwt_get_grant(jwt, "dest"));
	printf("aud: %s\n", jwt_get_grant(jwt, "aud"));
	printf("sub: %s\n", jwt_get_grant(jwt, "sub"));
	jwt_free(jwt);
	return false;
}
