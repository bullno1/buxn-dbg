#include "cmd.h"
#include <stdio.h>
#include <string.h>

void
print_cmd_list(void) {
	fprintf(stderr, "Available commands:\n\n");

	const buxn_dbg_cmd_entry_t* help = NULL;
	BUXN_DBG_CMD_FOREACH(cmd) {
		// Ensure that help is always printed last
		if (strcmp(cmd->name, "help") == 0) {
			help = cmd;
		} else if (strncmp("dev:", cmd->name, sizeof("dev:") - 1) != 0) {
			// Hide dev commands
			fprintf(stderr, "* %s: %s\n", cmd->name, cmd->description);
		}
	}

	if (help != NULL) {
		fprintf(stderr, "* %s: %s\n", help->name, help->description);
	}
}
