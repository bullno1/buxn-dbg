#include <stdio.h>
#include "bflag.h"
#include "cmd.h"
#include "common.h"
#include "server/server.h"

BUXN_DBG_CMD(
	server,
	"Start a debug server",
	"[flags]\n\n"
	"Available flags:\n\n"
	"* -connect=<transport>: How to connect to the debug target.\n"
	"  Default value: abstract-connect:buxn/vm\n"
	"  Available transports:\n\n"
	"  * file:<path>: Open a file at path\n"
	"  * tcp-connect:<address>:<port>: Connect to an address\n"
	"  * tcp-listen:<port>: Listen on a port for a single connection\n"
	"  * unix-connect:<name>: Connect to a unix domain socket\n"
	"  * unix-listen:<name>: Listen on a unix domain socket for a single connection\n"
	"  * abstract-connect:<name>: Connect to an abstract socket\n"
	"  * abstract-listen:<name>: Listen on an abstract socket for a single connection\n"
	"\n"
	"* -listen=<transport>: How to listen for debug clients.\n"
	"  Default value: abstract-listen:buxn/dbg\n"
	"  Available transports:\n\n"
	"  * tcp-listen:<port>: Listen on a tcp port\n"
	"  * unix-listen:<name>: Listen on a unix domain socket\n"
	"  * abstract-listen:<name>: Listen on an abstract socket\n"
) {
	buxn_dbg_server_args_t args;
	buxn_dbg_parse_transport("abstract-connect:buxn/vm", &args.connect_transport);
	buxn_dbg_parse_transport("abstract-listen:buxn/dbg", &args.listen_transport);
	bool connect_set = false;
	bool listen_set = false;

	for (int i = 1; i < argc; ++i) {
		const char* arg;
		if ((arg = parse_flag(argv[i], "-connect=")) != NULL) {
			if (connect_set) {
				fprintf(stderr, "-connect= can only be specified once");
				return 1;
			}

			if (!buxn_dbg_parse_transport(arg, &args.connect_transport)) {
				fprintf(stderr, "Invalid transport: %s\n", arg);
				return 1;
			}

			connect_set = true;
		} else if ((arg = parse_flag(argv[i], "-listen=")) != NULL) {
			if (listen_set) {
				fprintf(stderr, "-listen= can only be specified once");
				return 1;
			}

			if (
				!buxn_dbg_parse_transport(arg, &args.listen_transport)
				|| (args.listen_transport.type != BUXN_DBG_TRANSPORT_NET_LISTEN)
			) {
				fprintf(stderr, "Invalid transport: %s\n", arg);
				return 1;
			}

			listen_set = true;
		} else {
			fprintf(stderr, "Invalid flag: %s\n", argv[i]);
			return 1;
		}
	}

	return bio_enter(buxn_dbg_server_entry, &args);
}
