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

	buxn_dbg_client_t client;
	if (!buxn_dbg_make_client(&client, &args->connect_transport)) {
		return 1;
	}

	uint16_t pc;
	buxn_dbg_stack_info_t wst;
	buxn_dbg_stack_info_t rst;
	bio_call_status_t status;
	status = buxn_dbg_client_send_dbg_cmd(client, (buxn_dbg_cmd_t){
		.type = BUXN_DBG_CMD_INFO,
		.info = {
			.type = BUXN_DBG_INFO_PC,
			.pc = &pc,
		}
	});
	if (status != BIO_CALL_OK) { goto end; }

	status = buxn_dbg_client_send_dbg_cmd(client, (buxn_dbg_cmd_t){
		.type = BUXN_DBG_CMD_INFO,
		.info = {
			.type = BUXN_DBG_INFO_WST,
			.stack = &wst,
		}
	});
	if (status != BIO_CALL_OK) { goto end; }

	status = buxn_dbg_client_send_dbg_cmd(client, (buxn_dbg_cmd_t){
		.type = BUXN_DBG_CMD_INFO,
		.info = {
			.type = BUXN_DBG_INFO_RST,
			.stack = &rst,
		}
	});
	if (status != BIO_CALL_OK) { goto end; }

	BIO_INFO("pc = 0x%04x", pc);
	BIO_INFO("System/wst = %d", wst.pointer);
	BIO_INFO("System/rst = %d", rst.pointer);
end:
	buxn_dbg_stop_client(client);
	return 0;
}

BUXN_DBG_CMD(
	info,
	"Show information about the current state",
	"[flags]\n\n"
	"Available flags:\n\n"
	CONNECT_FLAG_HELP
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
