#include <l8w8jwt/decode.h>

static inline bool sessiontoken_isvalid(const char *token, const char *api_key,
		const char *api_secret_key, const char *shop)
{
	struct l8w8jwt_decoding_params params;
	l8w8jwt_decoding_params_init(&params);
	params.alg = L8W8JWT_ALG_HS256;
	params.jwt = (char *)token;
	params.jwt_length = strlen(token);
	params.verification_key = (unsigned char *)api_secret_key;
	params.verification_key_length = strlen(api_secret_key);
	params.validate_exp = 1;
	params.validate_nbf = 1;
	params.validate_aud = (char *)api_key;

	enum l8w8jwt_validation_result validation;
	struct l8w8jwt_claim *claims;
	size_t claims_len;
	int decode = l8w8jwt_decode(&params, &validation, &claims, &claims_len);

	struct l8w8jwt_claim *dest
		= l8w8jwt_get_claim(claims, claims_len, "dest", 4);
	_Bool iss_isvalid = !strncmp(dest->value,
			l8w8jwt_get_claim(claims, claims_len, "iss", 3)->value,
			dest->value_length);
	printf("JWT payload sub: %s\n",
			l8w8jwt_get_claim(claims, claims_len, "sub", 3)->value);
	l8w8jwt_free_claims(claims, claims_len);

	return decode == L8W8JWT_SUCCESS && validation == L8W8JWT_VALID
		&& iss_isvalid;
}
