#include <stdio.h>
#include "bflag.h"
#include "cmd.h"
#include "common.h"
#include "client.h"

typedef struct {
	buxn_dbg_transport_info_t connect_transport;
} args_t;

static int
bio_main(void* userdata) {
	args_t* args = userdata;

	bio_error_t error;
	BIO_DEBUG("Connecting to debug server");
	bio_socket_t sock;
	if (!bio_net_connect(
		BIO_SOCKET_STREAM,
		&args->connect_transport.net.addr,
		args->connect_transport.net.port,
		&sock,
		&error
	)) {
		BIO_ERROR(
			"Error while connecting: (" BIO_ERROR_FMT ")",
			BIO_ERROR_FMT_ARGS(&error)
		);
		return 1;
	}
	BIO_DEBUG("Connected to debug server");

	buxn_dbg_client_t client = buxn_dbg_start_client(&(buxn_dbg_client_args_t){
		.socket = sock,
	});

	uint16_t pc;
	bio_call_status_t status;
	status = buxn_dbg_client_send_dbg_cmd(client, (buxn_dbg_cmd_t){
		.type = BUXN_DBG_CMD_INFO,
		.info = {
			.type = BUXN_DBG_INFO_PC,
			.pc = &pc,
		}
	});
	if (status != BIO_CALL_OK) { goto end; }
	BIO_INFO("pc = 0x%04x", pc);

end:
	buxn_dbg_stop_client(client);
	bio_net_close(sock, NULL);
	return 0;
}

BUXN_DBG_CMD(
	info,
	"Show information about the current state",
	"[flags]\n\n"
	"Available flags:\n\n"
	"* -connect=<transport>: How to connect to the debug server.\n"
	"  Available transports:\n\n"
	"  * tcp-connect:<address>:<port>: Connect to an address\n"
	"  * unix-connect:<name>: Connect to a unix domain socket\n"
	"  * abstract-connect:<name>: Connect to an abstract socket\n"
	"\n"
	"  Default value: abstract-connect:buxn/dbg\n"
) {
	bool connect_set = false;
	args_t args;
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
		} else {
			fprintf(stderr, "Invalid flag: %s\n", argv[i]);
			return 1;
		}
	}

	return bio_enter(bio_main, &args);
}
