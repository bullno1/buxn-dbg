#include "cmd.h"
#include "common.h"
#include "client.h"
#include "logger.h"
#include "tui.h"
#include "breakpoint.h"
#include <bio/mailbox.h>

typedef struct {
	buxn_dbg_transport_info_t connect_transport;
} args_t;

typedef enum {
	MSG_INFO_PUSH,
	MSG_SET_FOCUS,
	MSG_BRKP_PUSH,
	MSG_QUIT,
} msg_type_t;

typedef struct {
	msg_type_t type;
	union {
		uint16_t focus;
		buxn_dbgx_info_t info_push;
		buxn_dbgx_brkp_push_t brkp_push;
	};
} msg_t;

typedef BIO_MAILBOX(msg_t) mailbox_t;

typedef struct {
	uint8_t focus;
	buxn_dbgx_info_t info;
	buxn_brkp_set_t brkps;
	mailbox_t main_mailbox;
	buxn_dbg_client_t client;
} tui_ctx_t;

static void
handle_notification(buxn_dbgx_msg_t msg, void* userdata) {
	mailbox_t mailbox = *(mailbox_t*)userdata;
	if (msg.type == BUXN_DBGX_MSG_SET_FOCUS) {
		msg_t msg_to_main = {
			.type = MSG_SET_FOCUS,
			.focus = msg.set_focus.address,
		};
		bio_wait_and_send_message(true, mailbox, msg_to_main);
	} else if (msg.type == BUXN_DBGX_MSG_INFO_PUSH) {
		msg_t msg_to_main = {
			.type = MSG_INFO_PUSH,
			.info_push = msg.info_push,
		};
		bio_wait_and_send_message(true, mailbox, msg_to_main);
	} else if (msg.type == BUXN_DBGX_MSG_BRKP_PUSH) {
		msg_t msg_to_main = {
			.type = MSG_BRKP_PUSH,
			.brkp_push = msg.brkp_push,
		};
		bio_wait_and_send_message(true, mailbox, msg_to_main);
	}
}

static void
tui_entry(buxn_tui_mailbox_t mailbox, void* userdata) {
	tui_ctx_t* ctx = userdata;

	bool should_run = true;
	int attribute = 0;
	while (bio_is_mailbox_open(mailbox) && should_run) {
		tb_clear();

		tb_printf(
			0, 0,
			TB_DEFAULT, TB_DEFAULT,
			"  id │ addr │ rwx │ pause │ where │"
		);
		tb_printf(
			0, 1,
			TB_DEFAULT, TB_DEFAULT,
			"─────┼──────┼─────┼───────┼───────┤"
		);

		for (uint8_t i = 1; i < ctx->brkps.nbrkps; ++i) {
			const buxn_dbg_brkp_t* brkp = &ctx->brkps.brkps[i];

			tb_printf(
				0, i + 1,
				TB_DEFAULT, TB_DEFAULT,
				"     │      │     │       │       │"
			);
			bool focused = i == ctx->focus;

			uintattr_t fg = brkp->mask != 0 ? TB_DEFAULT : TB_DIM;
			uintattr_t bg = TB_DEFAULT;
			if (focused) { fg |= TB_UNDERLINE; }
			if (i == ctx->info.brkp_id) { fg |= TB_RED; }

			// id
			tb_printf(2, i + 1, fg, bg, "%02x", i);

			// addr
			tb_printf(7, i + 1, fg, bg, "%04x", brkp->addr);

			// rwx
			bool r = (brkp->mask & BUXN_DBG_BRKP_LOAD) > 0;
			bool w = (brkp->mask & BUXN_DBG_BRKP_STORE) > 0;
			bool x = (brkp->mask & BUXN_DBG_BRKP_EXEC) > 0;
			tb_printf(
				14, i + 1,
				focused && attribute == 0 ? fg | TB_BLACK | TB_BOLD : fg,
				focused && attribute == 0 ? bg | TB_WHITE : bg,
				"%d", r
			);
			tb_printf(
				15, i + 1,
				focused && attribute == 1 ? fg | TB_BLACK | TB_BOLD : fg,
				focused && attribute == 1 ? bg | TB_WHITE : bg,
				"%d", w
			);
			tb_printf(
				16, i + 1,
				focused && attribute == 2 ? fg | TB_BLACK | TB_BOLD : fg,
				focused && attribute == 2 ? bg | TB_WHITE : bg,
				"%d", x
			);

			// pause
			bool pause = (brkp->mask & BUXN_DBG_BRKP_PAUSE) > 0;
			tb_printf(
				21, i + 1,
				focused && attribute == 3 ? fg | TB_BLACK | TB_BOLD : fg,
				focused && attribute == 3 ? bg | TB_WHITE : bg,
				"%s",
				pause ? "yes" : "no"
			);

			// where
			uint8_t where = brkp->mask & BUXN_DBG_BRKP_TYPE_MASK;
			tb_printf(
				29, i + 1,
				focused && attribute == 4 ? fg | TB_BLACK | TB_BOLD : fg,
				focused && attribute == 4 ? bg | TB_WHITE : bg,
				"%s", where == BUXN_DBG_BRKP_MEM ? "mem" : "dev"
			);
		}

		bio_tb_present();

		uint8_t old_focus = ctx->focus;
		buxn_tui_loop(msg, mailbox) {
			switch (buxn_tui_handle_event(&msg)) {
				case BUXN_TUI_QUIT:
					should_run = false;
					break;
				case BUXN_TUI_MOVE_LEFT:
					attribute = attribute > 0 ? attribute - 1 : 4;
					break;
				case BUXN_TUI_MOVE_RIGHT:
					attribute = (attribute + 1) % 5;
					break;
				case BUXN_TUI_MOVE_UP:
					if (ctx->focus > 1) { ctx->focus -= 1; }
					break;
				case BUXN_TUI_MOVE_DOWN:
					if (ctx->focus < ctx->brkps.nbrkps - 1) { ctx->focus += 1; }
					break;
				case BUXN_TUI_MOVE_TO_LINE_START:
					attribute = 0;
					break;
				case BUXN_TUI_MOVE_TO_LINE_END:
					attribute = 4;
					break;
				case BUXN_TUI_STEP:
					buxn_tui_execute_step(&msg, ctx->client);
					break;
				default:
					break;
			}
		}

		if (ctx->focus != old_focus) {
			const buxn_dbg_brkp_t* brkp = &ctx->brkps.brkps[ctx->focus];
			if (brkp->mask != 0) {
				buxn_dbg_client_set_focus(ctx->client, brkp->addr);
			}
		}
	}

	bio_wait_and_send_message(true, ctx->main_mailbox, (msg_t){ .type = MSG_QUIT });
}

static void
update_focus(tui_ctx_t* ui_ctx) {
	for (uint8_t i = 0; i < ui_ctx->brkps.nbrkps; ++i) {
		const buxn_dbg_brkp_t* brkp = &ui_ctx->brkps.brkps[i];
		if (brkp->mask == 0) { continue; }
		if (
			(brkp->mask & BUXN_DBG_BRKP_TYPE_MASK) == BUXN_DBG_BRKP_MEM
			&& brkp->addr == ui_ctx->info.focus
		) {
			ui_ctx->focus = i;
			break;
		}
	}

	if (ui_ctx->focus >= ui_ctx->brkps.nbrkps) {
		ui_ctx->focus = ui_ctx->brkps.nbrkps - 1;
	}
	if (ui_ctx->focus <= 0) {
		ui_ctx->focus = 1;
	}
}

static int
bio_main(void* userdata) {
	args_t* args = userdata;

	mailbox_t mailbox;
	bio_open_mailbox(&mailbox, 8);

	buxn_dbgx_info_t info = { 0 };
	buxn_dbg_client_t client;
	if (!buxn_dbg_make_client_ex(
		&client,
		&args->connect_transport,
		&(buxn_dbg_client_args_t){
			.userdata = &mailbox,
			.msg_handler = handle_notification,
		},
		&(buxn_dbgx_init_t){
			.client_name = "view:breakpoints",
			.subscriptions =
				  BUXN_DBGX_SUB_INFO_PUSH
				| BUXN_DBGX_SUB_FOCUS
				| BUXN_DBGX_SUB_BRKP,
			.options = BUXN_DBGX_INIT_OPT_INFO,
		},
		&(buxn_dbgx_init_rep_t){
			.info = &info,
		}
	)) {
		bio_close_mailbox(mailbox);
		return 1;
	}

	buxn_dbg_set_logger(buxn_dbg_add_net_logger(BIO_LOG_LEVEL_TRACE, "view:breakpoints"));

	tui_ctx_t ui_ctx = {
		.main_mailbox = mailbox,
		.info = info,
		.focus = 1,
		.client = client,
	};
	buxn_brkp_set_load(&ui_ctx.brkps, client);

	buxn_tui_t tui = buxn_tui_start(tui_entry, &ui_ctx);

	bio_foreach_message(msg, mailbox) {
		switch (msg.type) {
			case MSG_INFO_PUSH:
				ui_ctx.info = msg.info_push;
				update_focus(&ui_ctx);
				buxn_tui_refresh(tui);
				break;
			case MSG_SET_FOCUS:
				ui_ctx.info.focus = msg.focus;
				update_focus(&ui_ctx);
				buxn_tui_refresh(tui);
				break;
			case MSG_BRKP_PUSH:
				buxn_brkp_set_update(&ui_ctx.brkps, msg.brkp_push.id, msg.brkp_push.brkp);
				update_focus(&ui_ctx);
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

BUXN_DBG_CMD_EX(view_breakpoints, "view:breakpoints", "View breakpoints") {
	args_t args = { 0 };
	buxn_dbg_parse_transport("abstract-connect:buxn/dbg", &args.connect_transport);

	barg_opt_t opts[] = {
		barg_connect_opt(&args.connect_transport),
		barg_opt_hidden_help(),
	};
	barg_t barg = {
		.usage = "buxn-dbg view:breakpoints [options]",
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
