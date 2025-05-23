#ifndef BUXN_DBG_CMD_H
#define BUXN_DBG_CMD_H

#include <autolist.h>

typedef struct buxn_dbg_cmd_entry_s buxn_dbg_cmd_entry_t;

struct buxn_dbg_cmd_entry_s {
	const char* name;
	const char* description;
	int (*main)(const buxn_dbg_cmd_entry_t* self, int argc, const char** argv);
};

#define BUXN_DBG_CMD(NAME, DESCRIPTION) \
	BUXN_DBG_CMD_EX(NAME, #NAME, DESCRIPTION)

#define BUXN_DBG_CMD_EX(FUNCTION_NAME, DISPLAY_NAME, DESCRIPTION) \
	static int buxn_dbg_cmd_main_##FUNCTION_NAME(const buxn_dbg_cmd_entry_t* self, int argc, const char** argv); \
	AUTOLIST_ENTRY(buxn_dbg__commands, buxn_dbg_cmd_entry_t, buxn_dbg_cmd_entry_##FUNCTION_NAME) = { \
		.name = DISPLAY_NAME, \
		.description = DESCRIPTION, \
		.main = buxn_dbg_cmd_main_##FUNCTION_NAME, \
	}; \
	static int buxn_dbg_cmd_main_##FUNCTION_NAME(const buxn_dbg_cmd_entry_t* self, int argc, const char** argv)


AUTOLIST_DECLARE(buxn_dbg__commands)

#define BUXN_DBG_CMD_FOREACH(ITR) \
	AUTOLIST_FOREACH(buxn_dbg_cmd__itr, buxn_dbg__commands) \
		for ( \
			const buxn_dbg_cmd_entry_t* ITR = buxn_dbg_cmd__itr->value_addr; \
			ITR != NULL; \
			ITR = NULL \
		)

void
print_cmd_list(void);

#endif
