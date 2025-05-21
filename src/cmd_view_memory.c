#include "cmd.h"
#include "common.h"
#include "client.h"
#include "logger.h"
#include "tui.h"
#include "symbol.h"
#include <bio/mailbox.h>

#define NUM_HEADER_LINES 2
#define NUM_SPACES_PER_BYTE 3  // A space and 2 nibbles
#define BYTE_CHUNK_SIZE 2  // Always display each line as a group of 2 bytes

typedef struct {
	buxn_dbg_transport_info_t connect_transport;
	const char* dbg_filename;
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
	MSG_QUIT,
} msg_type_t;

typedef struct {
	msg_type_t type;

	union {
		struct {
			uint16_t start_address;
			uint16_t end_address;
			view_buffer_t* view_buffer;
		} refresh;
	};
} msg_t;

typedef BIO_MAILBOX(msg_t) mailbox_t;

typedef struct {
	mailbox_t main_mailbox;
	const buxn_dbg_symtab_t* symtab;
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

	int focus_address = 0x0100;  // reset vector
	int top_line = 0;
	view_buffer_t view_buffer = { 0 };

	bool should_run = true;
	while (bio_is_mailbox_open(mailbox) && should_run) {
		tb_clear();

		int width = tb_width();
		int height = tb_height();

		int num_bytes_per_row = (width / NUM_SPACES_PER_BYTE) / BYTE_CHUNK_SIZE * BYTE_CHUNK_SIZE;

		int focus_line = focus_address / num_bytes_per_row;
		if (focus_line < top_line) {
			top_line = focus_line;
		}

		int bottom_line = top_line + height - NUM_HEADER_LINES - 1;
		if (focus_line > bottom_line) {
			int movement = focus_line - bottom_line;
			top_line += movement;
			bottom_line += movement;
		}

		int start_address = top_line * num_bytes_per_row;
		int end_address = (bottom_line + 1) * num_bytes_per_row;  // exclusive
		if (end_address > UINT16_MAX) { end_address = UINT16_MAX; }

		// If the desired address range is not yet loaded, request a refresh
		int loading_start_addr = (int)view_buffer.loading_start_address;
		int loading_end_addr = (int)view_buffer.loading_end_address;
		if (!(
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
					.view_buffer = &view_buffer,
				},
			};
			bio_wait_and_send_message(true, ctx->main_mailbox, refresh_msg);
		}

		// Render based on what we have
		int loaded_start_addr = (int)view_buffer.loaded_start_address;
		int loaded_end_addr = (int)view_buffer.loaded_end_address;
		int symbol_index_hint = 0;
		for (int address = start_address; address < end_address; ++address) {
			int x = (address % num_bytes_per_row) * NUM_SPACES_PER_BYTE;
			int y = (address / num_bytes_per_row) - top_line + NUM_HEADER_LINES;

			const buxn_dbg_sym_t* symbol = NULL;
			if (ctx->symtab) {
				symbol = buxn_dbg_find_symbol(
					ctx->symtab, (uint16_t)address, &symbol_index_hint
				);
			}

			uintattr_t background = TB_DEFAULT;
			uintattr_t foreground = TB_DEFAULT;

			if (symbol == NULL) {
				foreground = TB_DEFAULT;
			} else if (symbol->type == BUXN_DBG_SYM_TEXT) {
				foreground = TB_GREEN;
			} else if (symbol->type == BUXN_DBG_SYM_OPCODE) {
				foreground = TB_CYAN;
			} else if (symbol->type == BUXN_DBG_SYM_NUMBER) {
				foreground = TB_RED;
			} else if (symbol->type == BUXN_DBG_SYM_LABEL_REF) {
				foreground = TB_YELLOW;
			}

			if (address == focus_address) {
				background = TB_WHITE;
				foreground |= TB_REVERSE;
			}

			if (loaded_start_addr <= address && address < loaded_end_addr) {
				uint8_t byte = view_buffer.buffer[address - loaded_start_addr];
				tb_printf(x, y, foreground, background, "%02x", byte);
			} else {
				tb_printf(x, y, foreground, background, "??");
			}
		}

		bio_tb_present();

		buxn_tui_loop(msg, mailbox) {
			switch (buxn_tui_handle_event(&msg)) {
				case BUXN_TUI_QUIT:
					should_run = false;
					break;
				case BUXN_TUI_MOVE_UP:
					focus_address -= num_bytes_per_row;
					if (focus_address < 0) { focus_address = 0; }
					break;
				case BUXN_TUI_MOVE_DOWN:
					focus_address += num_bytes_per_row;
					if (focus_address > UINT16_MAX) { focus_address = UINT16_MAX; }
					break;
				case BUXN_TUI_MOVE_LEFT:
					focus_address -= 1;
					if (focus_address < 0) { focus_address = 0; }
					break;
				case BUXN_TUI_MOVE_RIGHT:
					focus_address += 1;
					if (focus_address > UINT16_MAX) { focus_address = UINT16_MAX; }
					break;
				case BUXN_TUI_MOVE_TO_LINE_START:
					focus_address = focus_line * num_bytes_per_row;
					break;
				case BUXN_TUI_MOVE_TO_LINE_END:
					focus_address = (focus_line + 1) * num_bytes_per_row - 1;
					break;
				default:
					break;
			}
		}
	}

	bio_wait_and_send_message(true, ctx->main_mailbox, (msg_t){ .type = MSG_QUIT });
	buxn_dbg_free(view_buffer.buffer);
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

	buxn_dbg_symtab_t* symtab = NULL;
	if (args->dbg_filename != NULL) {
		symtab = buxn_dbg_load_symbols(args->dbg_filename);
	}
	if (symtab == NULL) {
		BIO_WARN("Semantic highlighting will not be available");
	}

	mailbox_t mailbox;
	bio_open_mailbox(&mailbox, 8);

	tui_ctx_t ui_ctx = {
		.main_mailbox = mailbox,
		.symtab = symtab,
	};
	buxn_tui_t tui = buxn_tui_start(tui_entry, &ui_ctx);

	uint8_t* load_buffer = NULL;
	size_t load_buffer_size = 0;

	bio_foreach_message(msg, mailbox) {
		switch (msg.type) {
			case MSG_REQUEST_REFRESH: {
				view_buffer_t* view_buffer = msg.refresh.view_buffer;
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
						vm_mem_read(
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
						vm_mem_read(
							client,
							requested_start_addr, load_size,
							load_buffer
						);
					}
				} else {
					vm_mem_read(
						client,
						requested_start_addr,
						requested_end_addr - requested_start_addr,
						load_buffer
					);
				}

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
			case MSG_QUIT:
				goto end;
		}
	}
end:

	buxn_tui_stop(tui);
	buxn_dbg_unload_symbols(symtab);
	buxn_dbg_free(load_buffer);

	bio_close_mailbox(mailbox);
	buxn_dbg_stop_client(client);
	return 0;
}

BUXN_DBG_CMD_EX(view_memory, "view:memory", "Show a hex dump of memory") {
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
				"If not specified, bytes will not be semantically highlighted.",
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
