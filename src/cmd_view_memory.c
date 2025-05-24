#include "cmd.h"
#include "common.h"
#include "client.h"
#include "logger.h"
#include "tui.h"
#include "symbol.h"
#include "breakpoint.h"
#include <buxn/vm/opcodes.h>
#include <bio/mailbox.h>

#define NUM_HEADER_LINES 1
#define NUM_SPACES_PER_BYTE 3  // A space and 2 nibbles
#define BYTE_CHUNK_SIZE 2  // Always display each line as a group of 2 bytes

#define DEFINE_OPCODE_NAME(NAME, VALUE) \
	[VALUE] = STRINGIFY(NAME),

#define STRINGIFY(X) STRINGIFY2(X)
#define STRINGIFY2(X) #X

static const char* opcode_names[256] = {
	BUXN_OPCODE_DISPATCH(DEFINE_OPCODE_NAME)
};

typedef struct {
	buxn_dbg_transport_info_t connect_transport;
} args_t;

typedef struct {
	uint8_t* buffer;
	uint16_t buffer_size;
	uint16_t loaded_start_address;
	uint16_t loaded_end_address;
	uint16_t loading_start_address;
	uint16_t loading_end_address;
} view_buffer_t;

typedef enum {
	MSG_REQUEST_REFRESH,
	MSG_SET_FOCUS,
	MSG_INFO_PUSH,
	MSG_BRKP_PUSH,
	MSG_QUIT,
} msg_type_t;

typedef struct {
	msg_type_t type;

	union {
		struct {
			uint16_t start_address;
			uint16_t end_address;
		} refresh;

		buxn_dbgx_set_focus_t set_focus;
		buxn_dbgx_info_t info_push;
		buxn_dbgx_brkp_push_t brkp_push;
	};
} msg_t;

typedef BIO_MAILBOX(msg_t) mailbox_t;

typedef struct {
	mailbox_t main_mailbox;
	const buxn_dbg_symtab_t* symtab;
	buxn_dbg_client_t client;
	view_buffer_t view_buffer;
	buxn_brkp_set_t brkps;
	int focus_address;
	int pc;
	bool vm_paused;
} tui_ctx_t;

static bio_call_status_t
vm_mem_read(
	buxn_dbg_client_t client,
	uint16_t addr, uint16_t size,
	uint8_t* target
) {
	// TODO: handle ranges larger than BUXN_DBG_MAX_MEM_ACCESS_SIZE
	buxn_dbg_cmd_t cmd = {
		.type = BUXN_DBG_CMD_MEM_READ,
		.mem_read = {
			.addr = addr,
			.size = size,
			.values = target,
		},
	};
	BIO_TRACE("Loading %d bytes from 0x%04x", size, addr);
	return buxn_dbg_client_send_dbg_cmd(client, cmd);
}

static void
tui_entry(buxn_tui_mailbox_t mailbox, void* userdata) {
	tui_ctx_t* ctx = userdata;

	int top_line = 0;

	bool should_run = true;
	while (bio_is_mailbox_open(mailbox) && should_run) {
		tb_clear();

		int width = tb_width();
		int height = tb_height();

		int num_bytes_per_row = (width / NUM_SPACES_PER_BYTE) / BYTE_CHUNK_SIZE * BYTE_CHUNK_SIZE;

		int focus_line = ctx->focus_address / num_bytes_per_row;
		if (focus_line < top_line) {
			top_line = focus_line;
		}

		int bottom_line = top_line + height - NUM_HEADER_LINES - 1 - 1;
		if (focus_line > bottom_line) {
			int movement = focus_line - bottom_line;
			top_line += movement;
			bottom_line += movement;
		}

		int start_address = top_line * num_bytes_per_row;
		int end_address = (bottom_line + 1) * num_bytes_per_row;  // exclusive
		if (end_address > UINT16_MAX) { end_address = UINT16_MAX; }

		// If the desired address range is not yet loaded, request a refresh
		int loading_start_addr = (int)ctx->view_buffer.loading_start_address;
		int loading_end_addr = (int)ctx->view_buffer.loading_end_address;
		if (ctx->vm_paused && !(
			loading_start_addr <= start_address
			&& start_address < loading_end_addr
			&& loading_start_addr <= end_address
			&& end_address <= loading_end_addr  // end addresses can overlap
		)) {
			msg_t refresh_msg = {
				.type = MSG_REQUEST_REFRESH,
				.refresh = {
					.start_address = (uint16_t)start_address,
					.end_address = (uint16_t)end_address,
				},
			};
			bio_wait_and_send_message(true, ctx->main_mailbox, refresh_msg);
		}

		// Render based on what we have
		int loaded_start_addr = (int)ctx->view_buffer.loaded_start_address;
		int loaded_end_addr = (int)ctx->view_buffer.loaded_end_address;
		int symbol_index_hint = 0;
		const buxn_dbg_sym_t* focused_symbol = NULL;
		uint8_t focused_byte = 0;
		bool focused_byte_is_known = false;
		for (int address = start_address; address < end_address; ++address) {
			int x = (address % num_bytes_per_row) * NUM_SPACES_PER_BYTE;
			int y = (address / num_bytes_per_row) - top_line + NUM_HEADER_LINES;

			const buxn_dbg_sym_t* symbol = NULL;
			if (ctx->symtab) {
				symbol = buxn_dbg_find_symbol(
					ctx->symtab, (uint16_t)address, &symbol_index_hint
				);

				if (address == ctx->focus_address) {
					focused_symbol = symbol;
				}
			}

			uintattr_t background = TB_DEFAULT;
			uintattr_t foreground = TB_DEFAULT;

			if (symbol == NULL) {
				foreground = ctx->symtab != NULL ? TB_DEFAULT | TB_DIM : TB_DEFAULT;
			} else if (symbol->type == BUXN_DBG_SYM_TEXT) {
				foreground = TB_GREEN;
			} else if (symbol->type == BUXN_DBG_SYM_OPCODE) {
				foreground = TB_CYAN;
			} else if (symbol->type == BUXN_DBG_SYM_NUMBER) {
				foreground = TB_RED;
			} else if (symbol->type == BUXN_DBG_SYM_LABEL_REF) {
				foreground = TB_YELLOW;
			} else if (symbol->type == BUXN_DBG_SYM_LABEL) {
				foreground = TB_DEFAULT | TB_BOLD;
			}

			if (address == ctx->pc) {
				background = TB_CYAN;
				foreground = TB_BLACK | TB_BOLD;
			}

			if (address == ctx->focus_address) {
				background = TB_WHITE;
				if (ctx->focus_address == ctx->pc) {
					foreground = TB_CYAN | TB_BOLD;
				} else {
					foreground = TB_BLACK | TB_BOLD;
				}
			}

			const buxn_dbg_brkp_t* brkp = buxn_brkp_set_find(
				&ctx->brkps, address, BUXN_DBG_BRKP_MEM
			);
			if (brkp != NULL) {
				background = TB_RED;
				foreground = TB_BLACK | TB_BOLD;
				if (address == ctx->focus_address) {
					foreground |= TB_UNDERLINE;
				}
			}

			if (loaded_start_addr <= address && address < loaded_end_addr) {
				uint8_t byte = ctx->view_buffer.buffer[address - loaded_start_addr];
				if (address == ctx->focus_address) {
					focused_byte = byte;
					focused_byte_is_known = true;
				}

				tb_printf(x, y, foreground, background, "%02x", byte);
			} else {
				tb_printf(x, y, foreground, background, "??");
			}
		}

		if (focused_symbol != NULL) {
			// Print type
			const char* type = "Unknown";
			switch (focused_symbol->type) {
				case BUXN_DBG_SYM_OPCODE:
					type = "opcode";
					break;
				case BUXN_DBG_SYM_TEXT:
					type = "text";
					break;
				case BUXN_DBG_SYM_NUMBER:
					type = "number";
					break;
				case BUXN_DBG_SYM_LABEL:
				case BUXN_DBG_SYM_LABEL_REF:
					type = "label";
					break;
			}
			if (focused_symbol->type == BUXN_DBG_SYM_OPCODE) {
				if (focused_byte_is_known) {
					tb_printf(0, 0, TB_WHITE, TB_DEFAULT, "Type: %s (%s)", type, opcode_names[focused_byte]);
				} else {
					tb_printf(0, 0, TB_WHITE, TB_DEFAULT, "Type: %s", type);
				}
			} else {
				tb_printf(0, 0, TB_WHITE, TB_DEFAULT, "Type: %s", type);
			}

			// Print source location
			const buxn_asm_source_region_t* region = &focused_symbol->region;
			buxn_tui_status_line_ex(
				TB_BLACK,
				ctx->vm_paused ? TB_WHITE : TB_RED,
				"[0x%04x] %s (%d:%d:%d - %d:%d:%d)",
				ctx->focus_address,
				region->filename,
				region->range.start.line, region->range.start.col, region->range.start.byte,
				region->range.end.line, region->range.end.col, region->range.end.byte
			);
		} else {
			// Dumb disassembly
			if (focused_byte_is_known) {
				tb_printf(
					0, 0,
					TB_DEFAULT,
					TB_DEFAULT,
					"Opcode: %s", opcode_names[focused_byte]
				);
			}
			buxn_tui_status_line_ex(
				TB_BLACK,
				ctx->vm_paused ? TB_WHITE : TB_RED,
				"[0x%04x]",
				ctx->focus_address
			);
		}

		bio_tb_present();

		int old_focus = ctx->focus_address;
		buxn_tui_loop(msg, mailbox) {
			switch (buxn_tui_handle_event(&msg)) {
				case BUXN_TUI_QUIT:
					should_run = false;
					break;
				case BUXN_TUI_MOVE_UP:
					ctx->focus_address -= num_bytes_per_row;
					if (ctx->focus_address < 0) { ctx->focus_address = 0; }
					break;
				case BUXN_TUI_MOVE_DOWN:
					ctx->focus_address += num_bytes_per_row;
					if (ctx->focus_address > UINT16_MAX) {
						ctx->focus_address = UINT16_MAX;
					}
					break;
				case BUXN_TUI_MOVE_LEFT:
					ctx->focus_address -= 1;
					if (ctx->focus_address < 0) { ctx->focus_address = 0; }
					break;
				case BUXN_TUI_MOVE_RIGHT:
					ctx->focus_address += 1;
					if (ctx->focus_address > UINT16_MAX) {
						ctx->focus_address = UINT16_MAX;
					}
					break;
				case BUXN_TUI_MOVE_TO_LINE_START:
					ctx->focus_address = focus_line * num_bytes_per_row;
					break;
				case BUXN_TUI_MOVE_TO_LINE_END:
					ctx->focus_address = (focus_line + 1) * num_bytes_per_row - 1;
					break;
				case BUXN_TUI_STEP:
					buxn_tui_execute_step(&msg, ctx->client);
					break;
				case BUXN_TUI_TOGGLE_BREAKPOINT:
					buxn_brkp_toggle(
						ctx->client, &ctx->brkps,
						ctx->focus_address,
						BUXN_DBG_BRKP_MEM | BUXN_DBG_BRKP_PAUSE,
						focused_symbol
					);
					break;
				default:
					break;
			}
		}

		if (ctx->focus_address != old_focus) {
			buxn_dbg_client_set_focus(ctx->client, ctx->focus_address);
		}
	}

	bio_wait_and_send_message(true, ctx->main_mailbox, (msg_t){ .type = MSG_QUIT });
}

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
	} else if (msg.type == BUXN_DBGX_MSG_BRKP_PUSH) {
		msg_t msg_to_main = {
			.type = MSG_BRKP_PUSH,
			.brkp_push = msg.brkp_push,
		};
		bio_wait_and_send_message(true, mailbox, msg_to_main);
	}
}

static int
bio_main(void* userdata) {
	args_t* args = userdata;

	mailbox_t mailbox;
	bio_open_mailbox(&mailbox, 8);

	buxn_dbgx_info_t info = { 0 };
	buxn_dbgx_config_t config = { 0 };
	buxn_dbg_client_t client;
	if (!buxn_dbg_make_client_ex(
		&client,
		&args->connect_transport,
		&(buxn_dbg_client_args_t){
			.userdata = &mailbox,
			.msg_handler = handle_notification,
		},
		&(buxn_dbgx_init_t){
			.client_name = "view:memory",
			.subscriptions =
				  BUXN_DBGX_SUB_INFO_PUSH
				| BUXN_DBGX_SUB_FOCUS
				| BUXN_DBGX_SUB_BRKP,
			.options = BUXN_DBGX_INIT_OPT_INFO | BUXN_DBGX_INIT_OPT_CONFIG,
		},
		&(buxn_dbgx_init_rep_t){
			.info = &info,
			.config = &config,
		}
	)) {
		bio_close_mailbox(mailbox);
		return 1;
	}

	buxn_dbg_set_logger(buxn_dbg_add_net_logger(BIO_LOG_LEVEL_TRACE, "view:memory"));

	buxn_dbg_symtab_t* symtab = NULL;
	if (config.dbg_filename != NULL) {
		symtab = buxn_dbg_load_symbols(config.dbg_filename);
	}
	if (symtab == NULL) {
		BIO_WARN("Semantic highlighting will not be available");
	}

	tui_ctx_t ui_ctx = {
		.main_mailbox = mailbox,
		.symtab = symtab,
		.client = client,
		.focus_address = info.focus,
		.pc = info.pc,
		.vm_paused = info.vm_paused,
	};
	buxn_brkp_set_load(&ui_ctx.brkps, client);
	buxn_tui_t tui = buxn_tui_start(tui_entry, &ui_ctx);

	uint8_t* load_buffer = NULL;
	size_t load_buffer_size = 0;

	bio_foreach_message(msg, mailbox) {
		switch (msg.type) {
			case MSG_REQUEST_REFRESH: {
				view_buffer_t* view_buffer = &ui_ctx.view_buffer;
				int requested_start_addr = (int)msg.refresh.start_address;
				int requested_end_addr = (int)msg.refresh.end_address;

				// Ensure the load buffer is big enough
				size_t required_size = requested_end_addr - requested_start_addr;
				if (required_size > load_buffer_size) {
					buxn_dbg_free(load_buffer);
					load_buffer = buxn_dbg_malloc(required_size);
					load_buffer_size = required_size;
				}

				// Tell the UI coro that we are loading
				view_buffer->loading_start_address = (uint16_t)requested_start_addr;
				view_buffer->loading_end_address = (uint16_t)requested_end_addr;

				// if the new address range overlaps the existing one, we don't
				// have to load everything
				bio_call_status_t load_status = BIO_CALL_OK;
				int loaded_start_addr = (int)view_buffer->loaded_start_address;
				int loaded_end_addr = (int)view_buffer->loaded_end_address;
				if (
					loaded_start_addr <= requested_start_addr
					&& requested_start_addr < loaded_end_addr
				) {
					int reuse_start_addr = requested_start_addr;
					int reuse_end_addr = requested_end_addr < loaded_end_addr
						? requested_end_addr
						: loaded_end_addr;
					int reuse_size = reuse_end_addr - reuse_start_addr;
					int load_size = requested_end_addr - reuse_end_addr;

					memcpy(
						&load_buffer[reuse_start_addr - requested_start_addr],
						&view_buffer->buffer[reuse_start_addr - loaded_start_addr],
						(size_t)reuse_size
					);
					if (load_size > 0) {
						load_status = vm_mem_read(
							client,
							reuse_end_addr, load_size,
							&load_buffer[reuse_end_addr - requested_start_addr]
						);
					}
				} else if (
					loaded_start_addr <= requested_end_addr
					&& requested_end_addr < loaded_end_addr
				) {
					int reuse_end_addr = requested_end_addr;
					int reuse_start_addr = requested_start_addr > loaded_start_addr
						? requested_start_addr
						: loaded_start_addr;
					int reuse_size = reuse_end_addr - reuse_start_addr;
					int load_size = reuse_start_addr - requested_start_addr;

					memcpy(
						&load_buffer[reuse_start_addr - requested_start_addr],
						&view_buffer->buffer[reuse_start_addr - loaded_start_addr],
						(size_t)reuse_size
					);
					if (load_size > 0) {
						load_status = vm_mem_read(
							client,
							requested_start_addr, load_size,
							load_buffer
						);
					}
				} else {
					load_status = vm_mem_read(
						client,
						requested_start_addr,
						requested_end_addr - requested_start_addr,
						load_buffer
					);
				}

				if (load_status != BIO_CALL_OK) { goto end; }

				// Swap the buffers
				{
					uint8_t* temp_ptr = view_buffer->buffer;
					view_buffer->buffer = load_buffer;
					load_buffer = temp_ptr;

					size_t temp_size = view_buffer->buffer_size;
					view_buffer->buffer_size = load_buffer_size;
					load_buffer_size = temp_size;
				}
				// Commit the load
				view_buffer->loaded_start_address = requested_start_addr;
				view_buffer->loaded_end_address = requested_end_addr;
				buxn_tui_refresh(tui);
			} break;
			case MSG_SET_FOCUS:
				ui_ctx.focus_address = msg.set_focus.address;
				buxn_tui_refresh(tui);
				break;
			case MSG_INFO_PUSH: {
				ui_ctx.focus_address = msg.info_push.focus;
				ui_ctx.pc = msg.info_push.pc;
				ui_ctx.vm_paused = msg.info_push.vm_paused;
				// Refresh view since a memory store might have happened
				if (msg.info_push.vm_paused) {
					vm_mem_read(
						client,
						ui_ctx.view_buffer.loaded_start_address,
						ui_ctx.view_buffer.loaded_end_address - ui_ctx.view_buffer.loaded_start_address,
						ui_ctx.view_buffer.buffer
					);
				}
				buxn_tui_refresh(tui);
			} break;
			case MSG_BRKP_PUSH: {
				buxn_brkp_set_update(&ui_ctx.brkps, msg.brkp_push.id, msg.brkp_push.brkp);
				buxn_tui_refresh(tui);
			} break;
			case MSG_QUIT:
				goto end;
		}
	}
end:

	buxn_tui_stop(tui);
	buxn_dbg_unload_symbols(symtab);
	buxn_dbg_free(load_buffer);
	buxn_dbg_free(ui_ctx.view_buffer.buffer);

	bio_close_mailbox(mailbox);
	buxn_dbg_stop_client(client);
	return 0;
}

BUXN_DBG_CMD_EX(view_memory, "view:memory", "Show a hex dump of memory") {
	args_t args = { 0 };
	buxn_dbg_parse_transport("abstract-connect:buxn/dbg", &args.connect_transport);

	barg_opt_t opts[] = {
		barg_connect_opt(&args.connect_transport),
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
