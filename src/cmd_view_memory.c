#include "cmd.h"
#include "common.h"
#include "client.h"
#include "logger.h"
#include "tui.h"
#include <bio/mailbox.h>

typedef struct {
	buxn_dbg_transport_info_t connect_transport;
	const char* dbg_filename;
	const char* src_dir;
} args_t;

typedef enum {
	MSG_REQUEST_REFRESH,
	MSG_QUIT,
} msg_type_t;

typedef struct {
	msg_type_t type;
} msg_t;

typedef BIO_MAILBOX(msg_t) mailbox_t;

typedef struct {
	mailbox_t main_mailbox;
} tui_ctx_t;

static void
tui_entry(buxn_tui_mailbox_t mailbox, void* userdata) {
	tui_ctx_t* ctx = userdata;

	bool should_run = true;
	while (bio_is_mailbox_open(mailbox) && should_run) {
		tb_clear();
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

	buxn_dbg_client_t client;
	if (!buxn_dbg_make_client(
		&client,
		&args->connect_transport,
		&(buxn_dbgx_init_t){ .client_name = "view:memory" }
	)) {
		return 1;
	}
	buxn_dbg_set_logger(buxn_dbg_add_net_logger(BIO_LOG_LEVEL_TRACE, client));

	mailbox_t mailbox;
	bio_open_mailbox(&mailbox, 8);

	tui_ctx_t ctx = {
		.main_mailbox = mailbox,
	};
	buxn_tui_t tui = buxn_tui_start(tui_entry, &ctx);

	bio_foreach_message(msg, mailbox) {
		switch (msg.type) {
			case MSG_REQUEST_REFRESH:
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

BUXN_DBG_CMD_EX(view_memory, "view:memory", "Show a hex dump of memory") {
	args_t args;
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
		.usage = "buxn-dbg view:memory [options]",
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
