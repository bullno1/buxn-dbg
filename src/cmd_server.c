#include "cmd.h"
#include "common.h"
#include "server/server.h"

BUXN_DBG_CMD(server, "Start a debug server") {
	buxn_dbg_server_args_t args;
	buxn_dbg_parse_transport("abstract-connect:buxn/vm", &args.connect_transport);
	buxn_dbg_parse_transport("abstract-listen:buxn/dbg", &args.listen_transport);

	barg_opt_t opts[] = {
		{
			.name = "connect",
			.short_name = 'c',
			.value_name = "transport",
			.parser = barg_transport(&args.connect_transport),
			.summary = "How to connect to the debug target",
			.description =
				"Default value: abstract-connect:buxn/vm\n"
				"Available transports:\n\n"
				"* file:<path>: Open a file at path\n"
				"* tcp-connect:<address>:<port>: Connect to an address\n"
				"* tcp-listen:<port>: Listen on a port for a single connection\n"
				"* unix-connect:<name>: Connect to a unix domain socket\n"
				"* unix-listen:<name>: Listen on a unix domain socket for a single connection\n"
				"* abstract-connect:<name>: Connect to an abstract socket\n"
				"* abstract-listen:<name>: Listen on an abstract socket for a single connection\n",
		},
		{
			.name = "listen",
			.short_name = 'l',
			.value_name = "transport",
			.parser = barg_connect_transport(&args.connect_transport),
			.summary = "How to listen for debug clients",
			.description =
				"Default value: abstract-listen:buxn/dbg\n"
				"Available transports:\n\n"
				"* tcp-listen:<port>: Listen on a tcp port\n"
				"* unix-listen:<name>: Listen on a unix domain socket\n"
				"* abstract-listen:<name>: Listen on an abstract socket\n",
		},
		barg_opt_hidden_help(),
	};
	barg_t barg = {
		.usage = "buxn-dbg server [options]",
		.summary = self->description,
		.opts = opts,
		.num_opts = sizeof(opts) / sizeof(opts[0]),
	};

	barg_result_t result = barg_parse(&barg, argc, argv);
	if (result.status != BARG_OK) {
		barg_print_result(&barg, result, stderr);
		return result.status == BARG_PARSE_ERROR;
	}

	return bio_enter(buxn_dbg_server_entry, &args);
}
