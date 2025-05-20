#include "cmd.h"
#include "client.h"
#include "common.h"
#include "logger.h"

typedef struct {
	buxn_dbg_transport_info_t connect_transport;
	bio_log_level_t log_level;
	const char* log_msg;
} args_t;

static int
bio_main(void* userdata) {
	args_t* args = userdata;

	buxn_dbg_client_t client;
	if (!buxn_dbg_make_client(&client, &args->connect_transport)) {
		return 1;
	}

	buxn_dbg_set_logger(buxn_dbg_add_net_logger(BIO_LOG_LEVEL_TRACE, client));
	BIO_LOG(args->log_level, "%s", args->log_msg);

	buxn_dbg_stop_client(client);
	return 0;
}

BUXN_DBG_CMD(log, "Log a message to the debug server") {
	args_t args = {
		.log_level = BIO_LOG_LEVEL_INFO,
	};
	buxn_dbg_parse_transport("abstract-connect:buxn/dbg", &args.connect_transport);

	barg_opt_t opts[] = {
		{
			.name = "connect",
			.short_name = 'c',
			.value_name = "transport",
			.parser = barg_transport(&args.connect_transport),
			.summary = "How to connect to the debug server",
			.description = CONNECT_TRANSPORT_OPT_DESC,
		},
		{
			.name = "log",
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
