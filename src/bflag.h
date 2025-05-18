#ifndef BFLAG_H
#define BFLAG_H

#include <string.h>

static inline
const char* parse_flag(const char* arg, const char* flag_name) {
	size_t flag_len = strlen(flag_name);
	if (strncmp(flag_name, arg, flag_len) == 0) {
		return arg + flag_len;
	} else {
		return NULL;
	}
}

#endif
