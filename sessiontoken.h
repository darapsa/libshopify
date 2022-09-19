#include <l8w8jwt/decode.h>

static inline bool sessiontoken_isvalid(const char *token, const char *key,
		const char *secret_key, const char *shop)
{
	struct l8w8jwt_decoding_params params;
	l8w8jwt_decoding_params_init(&params);
	params.alg = L8W8JWT_ALG_HS256;
	params.jwt = (char *)token;
	params.jwt_length = strlen(token);
	params.verification_key = (unsigned char *)secret_key;
	params.verification_key_length = strlen(secret_key);
	params.validate_exp = 1;
	params.validate_nbf = 1;
	params.validate_aud = (char *)key;
	enum l8w8jwt_validation_result validation;
	int decode = l8w8jwt_decode(&params, &validation, NULL,NULL);
	return decode == L8W8JWT_SUCCESS && validation == L8W8JWT_VALID;
}
