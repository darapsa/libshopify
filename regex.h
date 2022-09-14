#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>

static inline bool regex_match(const char *shop)
{
	pcre2_code *re = pcre2_compile((PCRE2_SPTR)
			"^[a-zA-Z0-9][a-zA-Z0-9\\-]*\\.myshopify\\.com",
			PCRE2_ZERO_TERMINATED, 0, &(int){ 0 },
			&(PCRE2_SIZE){ 0 }, NULL);
	pcre2_match_data *match_data
		= pcre2_match_data_create_from_pattern(re, NULL);
	int rc = pcre2_match(re, (PCRE2_SPTR)shop, strlen(shop), 0, 0,
			match_data, NULL);
	pcre2_match_data_free(match_data);
	pcre2_code_free(re);
	return rc >= 0;
}
