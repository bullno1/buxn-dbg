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

BUXN_DBG_CMD(info, "Show information about the current state") {
	args_t args = { 0 };
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
		barg_opt_hidden_help(),
	};
	barg_t barg = {
		.usage = "buxn-dbg info [options]",
		.summary = self->description,
		.num_opts = sizeof(opts) / sizeof(opts[0]),
		.opts = opts,
	};
	barg_result_t result = barg_parse(&barg, argc, argv);
	if (result.status != BARG_OK) {
		barg_print_result(&barg, result, stderr);
		return result.status == BARG_PARSE_ERROR;
	}

	return bio_enter(bio_main, &args);
}
