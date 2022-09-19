#include <json.h>

static inline void accesstoken_parse(const char *tok,
		struct shopify_session *session)
{
	json_tokener *tokener = json_tokener_new();
	json_object *obj = json_tokener_parse_ex(tokener, tok, strlen(tok));
	struct json_object_iterator iter = json_object_iter_begin(obj);
	struct json_object_iterator iter_end = json_object_iter_end(obj);
	while (!json_object_iter_equal(&iter, &iter_end)) {
		if (!strcmp(json_object_iter_peek_name(&iter),
					"access_token")) {
			const char *val = json_object_get_string(
					json_object_iter_peek_value(&iter));
			session->access_token = malloc(strlen(val) + 1);
			strcpy(session->access_token, val);
		} else if (!strcmp(json_object_iter_peek_name(&iter),
					"scope")) {
			const char *val = json_object_get_string(
					json_object_iter_peek_value(&iter));
			session->scopes = malloc(strlen(val) + 1);
			strcpy(session->scopes, val);
		}
		json_object_iter_next(&iter);
	}
	json_tokener_free(tokener);
}
