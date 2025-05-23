#include "cmd.h"
#include "common.h"
#include "client.h"
#include "logger.h"
#include "tui.h"
#include "symbol.h"
#include <bio/mailbox.h>

typedef struct {
	buxn_dbg_transport_info_t connect_transport;
	const char* dbg_filename;
} args_t;

typedef enum {
	MSG_SET_FOCUS,
	MSG_INFO_PUSH,
	MSG_QUIT,
} msg_type_t;

typedef struct {
	msg_type_t type;
	union {
		buxn_dbgx_set_focus_t set_focus;
		buxn_dbgx_info_t info_push;
	};
} msg_t;

typedef BIO_MAILBOX(msg_t) mailbox_t;

typedef enum {
	RST_FOCUS_UNKNOWN,
	RST_FOCUS_VECTOR,
	RST_FOCUS_RST,
	RST_FOCUS_PC,
} rst_focus_type_t;

typedef struct {
	buxn_dbg_stack_info_t stack;
	buxn_dbgx_info_t vm_info;
	mailbox_t main_mailbox;
	buxn_dbg_client_t client;
	buxn_dbg_symtab_t* symtab;
} tui_ctx_t;

static void
handle_notification(buxn_dbgx_msg_t msg, void* userdata) {
	mailbox_t mailbox = *(mailbox_t*)userdata;
	if (msg.type == BUXN_DBGX_MSG_SET_FOCUS) {
		msg_t msg_to_main = {
			.type = MSG_SET_FOCUS,
			.set_focus = msg.set_focus,
		};
		bio_wait_and_send_message(true, mailbox, msg_to_main);
	} else if (msg.type == BUXN_DBGX_MSG_INFO_PUSH) {
		msg_t msg_to_main = {
			.type = MSG_INFO_PUSH,
			.info_push = msg.info_push,
		};
		bio_wait_and_send_message(true, mailbox, msg_to_main);
	}
}

static void
print_src_loc_at(
	int x, int y,
	buxn_dbg_symtab_t* symtab,
	uint16_t pc
) {
	if (symtab == NULL) { return; }

	const buxn_dbg_sym_t* symbol = buxn_dbg_find_symbol(symtab, pc, NULL);
	if (symbol != NULL) {
		tb_printf(
			x, y,
			TB_DEFAULT | TB_DIM, TB_DEFAULT,
			"( %s:%d:%d )",
			symbol->region.filename,
			symbol->region.range.start.line, symbol->region.range.start.col
		);
	}
}

static void
tui_entry(buxn_tui_mailbox_t mailbox, void* userdata) {
	tui_ctx_t* ctx = userdata;

	bool should_run = true;
	const int label_x = 2;
	const int addr_x = 9;
	const int src_x = 17;
	rst_focus_type_t focus_type;
	int focus_index;
	while (bio_is_mailbox_open(mailbox) && should_run) {
		tb_clear();

		focus_type = RST_FOCUS_UNKNOWN;

		// Vector
		if (ctx->vm_info.vector_addr == ctx->vm_info.focus) {
			tb_printf(0, 0, TB_DEFAULT | TB_BOLD, TB_DEFAULT, ">");
			focus_type = RST_FOCUS_VECTOR;
		}
		tb_printf(
			label_x, 0,
			TB_DEFAULT | TB_BOLD, TB_DEFAULT,
			"vector"
		);
		tb_printf(
			addr_x, 0,
			TB_DEFAULT, TB_DEFAULT,
			"│ %04x",
			ctx->vm_info.vector_addr
		);
		print_src_loc_at(src_x, 0, ctx->symtab, ctx->vm_info.vector_addr);

		// Return stack from least current to most current
		tb_printf(
			label_x, 1,
			TB_DEFAULT | TB_BOLD, TB_DEFAULT,
			"rst",
			ctx->vm_info.vector_addr
		);
		for (int i = 0; i < ctx->stack.pointer; i += 2) {
			uint8_t return_hi = ctx->stack.data[i];
			uint8_t return_lo = ctx->stack.data[i + 1];
			uint16_t return_addr = return_hi << 8 | return_lo;
			int entry_y = i / 2 + 1;

			if (return_addr == ctx->vm_info.focus) {
				tb_printf(0, entry_y, TB_DEFAULT | TB_BOLD, TB_DEFAULT, ">");
				focus_type = RST_FOCUS_RST;
				focus_index = i / 2;
			}

			tb_printf(
				addr_x, entry_y,
				TB_DEFAULT, TB_DEFAULT,
				"│ %02x%02x",
				return_hi,
				return_lo
			);

			print_src_loc_at(
				src_x, entry_y,
				ctx->symtab,
				return_addr
			);
		}

		// pc
		int pc_line = (ctx->stack.pointer + 1) / 2 + 1;
		if (ctx->vm_info.pc == ctx->vm_info.focus) {
			tb_printf(0, pc_line, TB_DEFAULT | TB_BOLD, TB_DEFAULT, ">");
			focus_type = RST_FOCUS_PC;
		}
		tb_printf(
			label_x, pc_line,
			TB_DEFAULT | TB_BOLD, TB_DEFAULT,
			"pc"
		);
		tb_printf(
			addr_x, pc_line,
			TB_DEFAULT, TB_DEFAULT,
			"│ %04x",
			ctx->vm_info.pc
		);
		print_src_loc_at(src_x, pc_line, ctx->symtab, ctx->vm_info.pc);

		buxn_tui_status_line("System/rst: 0x%02d", ctx->stack.pointer);

		bio_tb_present();

		bool moved = false;
		buxn_tui_loop(msg, mailbox) {
			switch (buxn_tui_handle_event(&msg)) {
				case BUXN_TUI_MOVE_UP:
				case BUXN_TUI_MOVE_LEFT:
					moved = true;
					switch (focus_type) {
						case RST_FOCUS_UNKNOWN:
						case RST_FOCUS_PC: {
							int rst_depth = ctx->stack.pointer / 2;
							if (rst_depth > 0) {
								focus_type = RST_FOCUS_RST;
								focus_index = rst_depth - 1;
							} else {
								focus_type = RST_FOCUS_VECTOR;
							}
						} break;
						case RST_FOCUS_RST: {
							if (focus_index > 0) {
								focus_index -= 1;
							} else {
								focus_type = RST_FOCUS_VECTOR;
							}
						} break;
						case RST_FOCUS_VECTOR: {
							focus_type = RST_FOCUS_PC;
						} break;
					}
					break;
				case BUXN_TUI_MOVE_DOWN:
				case BUXN_TUI_MOVE_RIGHT:
					moved = true;
					switch (focus_type) {
						case RST_FOCUS_PC: {
							focus_type = RST_FOCUS_VECTOR;
						} break;
						case RST_FOCUS_RST: {
							int rst_depth = ctx->stack.pointer / 2;
							if (focus_index < rst_depth - 1) {
								focus_index += 1;
							} else {
								focus_type = RST_FOCUS_PC;
							}
						} break;
						case RST_FOCUS_UNKNOWN:
						case RST_FOCUS_VECTOR: {
							int rst_depth = ctx->stack.pointer / 2;
							if (rst_depth > 0) {
								focus_type = RST_FOCUS_RST;
								focus_index = 0;
							} else {
								focus_type = RST_FOCUS_PC;
							}
						} break;
					}
					break;
				case BUXN_TUI_MOVE_TO_LINE_START:
					moved = true;
					focus_type = RST_FOCUS_VECTOR;
					break;
				case BUXN_TUI_MOVE_TO_LINE_END:
					moved = true;
					focus_type = RST_FOCUS_PC;
					break;
				case BUXN_TUI_STEP:
					buxn_tui_execute_step(&msg, ctx->client);
					break;
				case BUXN_TUI_QUIT:
					should_run = false;
					break;
				default:
					break;
			}
		}

		uint16_t next_focus;
		switch (focus_type) {
			case RST_FOCUS_UNKNOWN:
			case RST_FOCUS_PC:
				next_focus = ctx->vm_info.pc;
				break;
			case RST_FOCUS_VECTOR:
				next_focus = ctx->vm_info.vector_addr;
				break;
			case RST_FOCUS_RST: {
				uint8_t return_hi = ctx->stack.data[focus_index * 2];
				uint8_t return_lo = ctx->stack.data[focus_index * 2 + 1];
				next_focus = return_hi << 8 | return_lo;
			} break;
		}

		if (moved && next_focus != ctx->vm_info.focus) {
			buxn_dbg_client_send(ctx->client, (buxn_dbgx_msg_t){
				.type = BUXN_DBGX_MSG_SET_FOCUS,
				.set_focus = { .address = next_focus },
			});
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
		&(buxn_dbgx_init_t){ .client_name = "view:rst" }
	)) {
		return 1;
	}
	buxn_dbg_set_logger(buxn_dbg_add_net_logger(BIO_LOG_LEVEL_TRACE));

	tui_ctx_t ui_ctx = {
		.main_mailbox = mailbox,
		.client = client,
	};

	buxn_dbg_client_send_dbg_cmd(client, (buxn_dbg_cmd_t){
		.type = BUXN_DBG_CMD_INFO,
		.info = {
			.type = BUXN_DBG_INFO_RST,
			.stack = &ui_ctx.stack,
		},
	});
	bio_call_status_t status = buxn_dbg_client_send(client, (buxn_dbgx_msg_t){
		.type = BUXN_DBGX_MSG_INFO_REQ,
		.info = &ui_ctx.vm_info,
	});
	if (status != BIO_CALL_OK) {
		return 1;
	}

	buxn_dbg_symtab_t* symtab = NULL;
	if (args->dbg_filename != NULL) {
		symtab = buxn_dbg_load_symbols(args->dbg_filename);
	}
	if (symtab == NULL) {
		BIO_WARN("Return stack will not be annotated");
	}
	ui_ctx.symtab = symtab;

	buxn_tui_t tui = buxn_tui_start(tui_entry, &ui_ctx);

	bio_foreach_message(msg, mailbox) {
		switch (msg.type) {
			case MSG_SET_FOCUS:
				ui_ctx.vm_info.focus = msg.set_focus.address;
				buxn_tui_refresh(tui);
				break;
			case MSG_INFO_PUSH:
				ui_ctx.vm_info = msg.info_push;
				buxn_dbg_client_send_dbg_cmd(client, (buxn_dbg_cmd_t){
					.type = BUXN_DBG_CMD_INFO,
					.info = {
						.type = BUXN_DBG_INFO_RST,
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
	buxn_dbg_unload_symbols(symtab);
	bio_close_mailbox(mailbox);
	buxn_dbg_stop_client(client);
	return 0;
}

BUXN_DBG_CMD_EX(view_rst, "view:rst", "View the return stack") {
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
		{
			.name = "dbg-file",
			.short_name = 'd',
			.value_name = "path",
			.parser = barg_str(&args.dbg_filename),
			.summary = "Path to the .rom.dbg file",
			.description =
				"If not specified, the return stack with not be annotated.",
		},
		barg_opt_hidden_help(),
	};
	barg_t barg = {
		.usage = "buxn-dbg view:rst [options]",
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
