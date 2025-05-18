#include "cmd.h"
#include <string.h>
#include <stdio.h>

BUXN_DBG_CMD(
	help,
	"Show how to use a command",
	"<command>\n"
) {
	if (argc != 2) {
		print_cmd_usage(self);
		return 1;
	}

	const char* cmd_name = argv[1];
	BUXN_DBG_CMD_FOREACH(cmd) {
		if (strcmp(cmd->name, cmd_name) == 0) {
			print_cmd_usage(cmd);
			return 0;
		}
	}

	fprintf(stderr, "Invalid commandd: %s\n", cmd_name);
	print_cmd_list();

	return 1;
}
