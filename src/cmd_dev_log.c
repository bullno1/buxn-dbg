#include "cmd.h"
#include "common.h"
#include "logger.h"

typedef struct {
	bio_log_level_t log_level;
	const char* log_msg;
} args_t;

static int
bio_main(void* userdata) {
	args_t* args = userdata;

	bio_logger_t logger = buxn_dbg_add_net_logger(BIO_LOG_LEVEL_TRACE, "dev:log");
	BIO_LOG(args->log_level, "%s", args->log_msg);
	bio_remove_logger(logger);

	return 0;
}

BUXN_DBG_CMD_EX(dev_log, "dev:log", "Log a message to the log server") {
	args_t args = {
		.log_level = BIO_LOG_LEVEL_INFO,
	};

	barg_opt_t opts[] = {
		{
			.name = "level",
			.short_name = 'l',
			.value_name = "level",
			.parser = barg_log_level(&args.log_level),
			.summary = "Set the log level",
			.description = LOG_LEVEL_OPT_DESC,
		},
		barg_opt_hidden_help(),
	};
	barg_t barg = {
		.usage = "buxn-dbg log [options] <message>",
		.summary = self->description,
		.num_opts = sizeof(opts) / sizeof(opts[0]),
		.opts = opts,
		.allow_positional = true,
	};

	barg_result_t result = barg_parse(&barg, argc, argv);
	if (result.status != BARG_OK) {
		barg_print_result(&barg, result, stderr);
		return result.status == BARG_PARSE_ERROR;
	}

	if (result.arg_index >= argc) {
		fprintf(stderr, "A log message is required\n");
		return 1;
	} else if (result.arg_index != argc - 1) {
		fprintf(stderr, "Only one message is allowed\n");
		return 1;
	} else {
		args.log_msg = argv[result.arg_index];
		return bio_enter(bio_main, &args);
	}
}
