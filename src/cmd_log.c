#include "bflag.h"
#include "cmd.h"
#include "client.h"
#include "common.h"
#include <stdio.h>

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

	buxn_dbg_client_send(client, (buxn_dbgx_msg_t){
		.type = BUXN_DBGX_MSG_LOG,
		.log = {
			.file = __FILE__,
			.line = __LINE__,
			.level = args->log_level,
			.msg = args->log_msg,
		},
	});

	buxn_dbg_stop_client(client);
	return 0;
}

BUXN_DBG_CMD(
	log,
	"Log a message to the debug server",
	"[flags] <msg>\n\n"
	"Available flags:\n\n"
	CONNECT_FLAG_HELP
	"* -level=<level>: Log level.\n"
	"  Default level: info\n"
	"  Valid levels:\n\n"
	"  * trace\n"
	"  * debug\n"
	"  * info\n"
	"  * warn\n"
	"  * error\n"
	"  * fatal\n"
) {
	bool connect_set = false;
	bool level_set = false;
	args_t args = {
		.log_level = BIO_LOG_LEVEL_INFO,
	};
	buxn_dbg_parse_transport("abstract-connect:buxn/dbg", &args.connect_transport);
	for (int i = 1; i < argc; ++i) {
		const char* arg;
		if ((arg = parse_flag(argv[i], "-connect=")) != NULL) {
			if (connect_set) {
				fprintf(stderr, "-connect= can only be specified once");
				return 1;
			}

			if (
				!buxn_dbg_parse_transport(arg, &args.connect_transport)
				|| args.connect_transport.type != BUXN_DBG_TRANSPORT_NET_CONNECT
			) {
				fprintf(stderr, "Invalid transport: %s\n", arg);
				return 1;
			}

			connect_set = true;
		} else if ((arg = parse_flag(argv[i], "-level=")) != NULL) {
			if (level_set) {
				fprintf(stderr, "-level= can only be specified once");
				return 1;
			}

			if (strcmp(arg, "trace") == 0) {
				args.log_level = BIO_LOG_LEVEL_TRACE;
			} else if (strcmp(arg, "debug") == 0) {
				args.log_level = BIO_LOG_LEVEL_DEBUG;
			} else if (strcmp(arg, "info") == 0) {
				args.log_level = BIO_LOG_LEVEL_INFO;
			} else if (strcmp(arg, "warn") == 0) {
				args.log_level = BIO_LOG_LEVEL_WARN;
			} else if (strcmp(arg, "error") == 0) {
				args.log_level = BIO_LOG_LEVEL_ERROR;
			} else if (strcmp(arg, "fatal") == 0) {
				args.log_level = BIO_LOG_LEVEL_FATAL;
			} else {
				fprintf(stderr, "Invalid log level: %s\n", arg);
				return 1;
			}

			level_set = true;
		} else {
			if (args.log_msg == NULL) {
				args.log_msg = argv[i];
			} else {
				fprintf(stderr, "Only one message is allowed\n");
				return 1;
			}
		}
	}

	if (args.log_msg == NULL) {
		fprintf(stderr, "A log message is required\n");
		return 1;
	}

	return bio_enter(bio_main, &args);
}
