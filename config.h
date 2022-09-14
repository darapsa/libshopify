#include <toml.h>

static inline void config_getscopes(const char *scope_path, char **scopes)
{
	FILE *fp = fopen(scope_path, "r");
	toml_table_t* toml = toml_parse_file(fp, NULL, 0);
	fclose(fp);
	*scopes = toml_string_in(toml, "scopes").u.s;
	toml_free(toml);
}
