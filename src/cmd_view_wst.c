#include "cmd.h"
#include "common.h"
#include "client.h"
#include "logger.h"
#include "tui.h"
#include <bio/mailbox.h>

#define NUM_SPACES_PER_BYTE 3  // A space and 2 nibbles

typedef struct {
	buxn_dbg_transport_info_t connect_transport;
} args_t;

typedef enum {
	MSG_INFO_PUSH,
	MSG_QUIT,
} msg_type_t;

typedef struct {
	msg_type_t type;
} msg_t;

typedef BIO_MAILBOX(msg_t) mailbox_t;

typedef struct {
	buxn_dbg_stack_info_t stack;
	mailbox_t main_mailbox;
} tui_ctx_t;

static void
handle_notification(buxn_dbgx_msg_t msg, void* userdata) {
	mailbox_t mailbox = *(mailbox_t*)userdata;
	if (msg.type == BUXN_DBGX_MSG_INFO_PUSH) {
		msg_t msg_to_main = {
			.type = MSG_INFO_PUSH,
		};
		bio_wait_and_send_message(true, mailbox, msg_to_main);
	}
}

static void
tui_entry(buxn_tui_mailbox_t mailbox, void* userdata) {
	tui_ctx_t* ctx = userdata;

	bool should_run = true;
	while (bio_is_mailbox_open(mailbox) && should_run) {
		tb_clear();
		int width = tb_width();
		int num_bytes_per_row = width / NUM_SPACES_PER_BYTE;
		for (int i = 0; i < ctx->stack.pointer; ++i) {
			int x = (i % num_bytes_per_row) * NUM_SPACES_PER_BYTE;
			int y = (i / num_bytes_per_row);
			tb_printf(x, y, TB_DEFAULT, TB_DEFAULT, "%02x", ctx->stack.data[i]);
		}

		buxn_tui_status_line("System/wst: 0x%02d", ctx->stack.pointer);

		bio_tb_present();

		buxn_tui_loop(msg, mailbox) {
			switch (buxn_tui_handle_event(&msg)) {
				case BUXN_TUI_QUIT:
					should_run = false;
					break;
				default:
					break;
			}
		}
	}

	bio_wait_and_send_message(true, ctx->main_mailbox, (msg_t){ .type = MSG_QUIT });
}

static int
bio_main(void* userdata) {
	args_t* args = userdata;

	mailbox_t mailbox;
	bio_open_mailbox(&mailbox, 8);

	buxn_dbg_client_t client;
	if (!buxn_dbg_make_client_ex(
		&client,
		&args->connect_transport,
		&(buxn_dbg_client_args_t){
			.userdata = &mailbox,
			.msg_handler = handle_notification,
		},
		&(buxn_dbgx_init_t){ .client_name = "view:wst" }
	)) {
		return 1;
	}
	buxn_dbg_set_logger(buxn_dbg_add_net_logger(BIO_LOG_LEVEL_TRACE, client));

	tui_ctx_t ui_ctx = {
		.main_mailbox = mailbox,
	};
	buxn_dbg_client_send_dbg_cmd(client, (buxn_dbg_cmd_t){
		.type = BUXN_DBG_CMD_INFO,
		.info = {
			.type = BUXN_DBG_INFO_WST,
			.stack = &ui_ctx.stack,
		},
	});

	buxn_tui_t tui = buxn_tui_start(tui_entry, &ui_ctx);

	bio_foreach_message(msg, mailbox) {
		switch (msg.type) {
			case MSG_INFO_PUSH:
				buxn_dbg_client_send_dbg_cmd(client, (buxn_dbg_cmd_t){
					.type = BUXN_DBG_CMD_INFO,
					.info = {
						.type = BUXN_DBG_INFO_WST,
						.stack = &ui_ctx.stack,
					},
				});
				buxn_tui_refresh(tui);
				break;
			case MSG_QUIT:
				goto end;
		}
	}
end:

	buxn_tui_stop(tui);
	bio_close_mailbox(mailbox);
	buxn_dbg_stop_client(client);
	return 0;
}

BUXN_DBG_CMD_EX(view_wst, "view:wst", "View the working stack") {
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
		.usage = "buxn-dbg view:wst [options]",
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
