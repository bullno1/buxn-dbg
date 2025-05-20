#include "barg.h"
#include "common.h"
#include "cmd.h"
#include <string.h>
#include <stdio.h>

static int
print_cmd_usage(const buxn_dbg_cmd_entry_t* cmd) {
	const char* help_argv[] = { cmd->name, "--help" };
	int help_argc = (int)(sizeof(help_argv) / sizeof(help_argv[0]));
	return cmd->main(cmd, help_argc, help_argv);
}

BUXN_DBG_CMD(help, "Show how to use a command") {
	barg_opt_t opts[] = {
		barg_opt_hidden_help(),
	};
	barg_t barg = {
		.usage = "buxn-dbg help <command>",
		.summary = self->description,
		.opts = opts,
		.num_opts = sizeof(opts) / sizeof(opts[0]),
		.allow_positional = true,
	};

	barg_result_t result = barg_parse(&barg, argc, argv);
	if (result.status != BARG_OK) {
		barg_print_result(&barg, result, stderr);
		return result.status == BARG_PARSE_ERROR;
	}

	if (result.arg_index != argc - 1) {
		fprintf(stderr, "Please provide exactly one command\n");
		print_cmd_usage(self);
		return 1;
	}

	const char* cmd_name = argv[result.arg_index];
	BUXN_DBG_CMD_FOREACH(cmd) {
		if (strcmp(cmd->name, cmd_name) == 0) {
			return print_cmd_usage(cmd);
		}
	}

	fprintf(stderr, "Invalid command: %s\n", cmd_name);
	print_cmd_list();

	return 1;
}
