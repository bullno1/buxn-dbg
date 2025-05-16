#include "cmd.h"
#include <stdio.h>
#include <string.h>

void
print_cmd_list(void) {
	fprintf(stderr, "Available commands:\n\n");

	const buxn_dbg_cmd_entry_t* help = NULL;
	BUXN_DBG_CMD_FOREACH(cmd) {
		// Ensure that help is always printed last
		if (strcmp(cmd->name, "help") != 0) {
			fprintf(stderr, "* %s: %s\n", cmd->name, cmd->description);
		} else {
			help = cmd;
		}
	}

	if (help != NULL) {
		fprintf(stderr, "* %s: %s\n", help->name, help->description);
	}
}

void
print_cmd_usage(const buxn_dbg_cmd_entry_t* cmd) {
	fprintf(stderr, "Usage: buxn-dbg %s %s\n", cmd->name, cmd->help);
}
