#include <buxn/dbg/core.h>
#include <autolist.h>
#include <stdio.h>
#include <string.h>
#include "cmd.h"

int
main(int argc, const char* argv[]) {
	if (argc < 2) {
		fprintf(stderr, "Usage: buxn-dbg <command> [arguments]\n\n");
		print_cmd_list();

		return 1;
	}

	const char* cmd_name = argv[1];
	BUXN_DBG_CMD_FOREACH(cmd) {
		if (strcmp(cmd->name, cmd_name) == 0) {
			return cmd->main(cmd, argc - 1, argv + 1);
		}
	}

	fprintf(stderr, "Invalid command: %s\n", cmd_name);
	print_cmd_list();

	return 1;
}
