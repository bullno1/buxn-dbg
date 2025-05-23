#include "cmd.h"
#include "common.h"
#include "client.h"
#include "logger.h"
#include "tui.h"
#include "symbol.h"
#include <bio/mailbox.h>
#include <bio/file.h>
#include <bhash.h>
#include <barray.h>

typedef struct {
	buxn_dbg_transport_info_t connect_transport;
} args_t;

typedef struct {
	const char* content;
	int len;
	barray(const buxn_dbg_sym_t*) symbols;
} source_line_t;

typedef struct {
	char* content;
	int size;
	barray(source_line_t) lines;
} source_t;

typedef BHASH_TABLE(const char*, source_t) source_set_t;

typedef enum {
	MSG_LOAD_SOURCE,
	MSG_SET_FOCUS,
	MSG_INFO_PUSH,
	MSG_QUIT,
} msg_type_t;

typedef struct {
	msg_type_t type;

	union {
		struct {
			const char* name;
		} load_source;

		buxn_dbgx_set_focus_t set_focus;
		buxn_dbgx_info_t info_push;
	};
} msg_t;

typedef BIO_MAILBOX(msg_t) mailbox_t;

typedef struct {
	mailbox_t main_mailbox;
	buxn_dbg_client_t client;
	const buxn_dbg_symtab_t* symtab;
	source_set_t* source_set;
	uint16_t focus_address;
	uint16_t pc;
} tui_ctx_t;

static void
tui_entry(buxn_tui_mailbox_t mailbox, void* userdata) {
	tui_ctx_t* ctx = userdata;

	int top_line = 1;
	int focus_line = 1;

	bool should_run = true;
	const buxn_dbg_sym_t* focused_symbol = buxn_dbg_find_symbol(
		ctx->symtab, ctx->focus_address, NULL
	);
	if (focused_symbol == NULL) {
		focused_symbol = buxn_dbg_find_symbol(ctx->symtab, ctx->pc, NULL);
	}

	while (bio_is_mailbox_open(mailbox) && should_run) {
		tb_clear();

		int width = tb_width();
		int height = tb_height();
		int column_offset = 0;
		const buxn_dbg_sym_t* pc_symbol = buxn_dbg_find_symbol(
			ctx->symtab, ctx->pc, NULL
		);

		const buxn_dbg_sym_t* new_focused_symbol = buxn_dbg_find_symbol(
			ctx->symtab, ctx->focus_address, NULL
		);
		if (new_focused_symbol != NULL) {
			focused_symbol = new_focused_symbol;
		}

		if (focused_symbol != NULL) {
			focus_line = focused_symbol->region.range.start.line;
			// Move right as little as possible to make the entire symbol visible
			if (focused_symbol->region.range.end.col > width) {
				column_offset = focused_symbol->region.range.end.col - width;
			}
		}

		const char* focused_filename = NULL;
		if (focused_symbol != NULL) {
			focused_filename = focused_symbol->region.filename;
		}
		bhash_index_t index = -1;
		if (focused_filename != NULL) {
			index = bhash_find(ctx->source_set, focused_filename);
		}

		source_t source = { 0 };
		if (bhash_is_valid(index)) {
			source = ctx->source_set->values[index];
		} else if (focused_filename != NULL) {
			// Ask main to load it
			msg_t msg = {
				.type = MSG_LOAD_SOURCE,
				.load_source.name = focused_filename,
			};
			bio_wait_and_send_message(true, ctx->main_mailbox, msg);
		}

		if (focus_line < top_line) {
			top_line = focus_line;
		}

		int bottom_line = top_line + height - 2;  // Space for status line
		if (focus_line > bottom_line) {
			int movement = focus_line - bottom_line;
			top_line += movement;
			bottom_line += movement;
		}

		int num_lines = barray_len(source.lines);
		for (int line = top_line; line <= bottom_line; ++line) {
			if (line > num_lines) { break; }

			const source_line_t* source_line = &source.lines[line - 1];
			if (column_offset < source_line->len) {
				tb_printf(
					0, line - top_line,
					TB_DEFAULT | TB_DIM, TB_DEFAULT,
					"%.*s",
					source_line->len - column_offset,
					source_line->content + column_offset
				);
			}

			// Semantic highlighting by drawing over the current line
			for (int i = 0; i < (int)barray_len(source_line->symbols); ++i) {
				const buxn_dbg_sym_t* symbol = source_line->symbols[i];
				const buxn_asm_file_range_t* range = &symbol->region.range;
				if (range->start.line > line) {
					break;
				}

				const char* str = source.content + range->start.byte;
				int str_len = range->end.byte - range->start.byte;

				uintattr_t background = TB_DEFAULT;
				uintattr_t foreground = TB_DEFAULT;
				if (symbol->type == BUXN_DBG_SYM_TEXT) {
					foreground = TB_GREEN;
				} else if (symbol->type == BUXN_DBG_SYM_OPCODE) {
					foreground = TB_CYAN;
				} else if (symbol->type == BUXN_DBG_SYM_NUMBER) {
					foreground = TB_RED;
				} else if (symbol->type == BUXN_DBG_SYM_LABEL_REF) {
					foreground = TB_YELLOW;
				} else if (symbol->type == BUXN_DBG_SYM_LABEL) {
					foreground = TB_WHITE | TB_BOLD;
				}

				if (
					pc_symbol != NULL
					&& (
						symbol == pc_symbol
						|| (
							symbol->region.filename == pc_symbol->region.filename
							&& symbol->region.range.start.byte == pc_symbol->region.range.start.byte
							&& symbol->region.range.end.byte == pc_symbol->region.range.end.byte
						)
					)
				) {
					background = TB_CYAN;
					foreground = TB_BLACK | TB_BOLD;
				}

				if (
					focused_symbol != NULL
					&& (
						symbol == focused_symbol
						|| (
							symbol->region.filename == focused_symbol->region.filename
							&& symbol->region.range.start.byte == focused_symbol->region.range.start.byte
							&& symbol->region.range.end.byte == focused_symbol->region.range.end.byte
						)
					)
				) {
					background = TB_WHITE;
					if (focused_symbol == pc_symbol) {
						foreground = TB_CYAN | TB_BOLD;
					} else {
						foreground = TB_BLACK | TB_BOLD;
					}
				}

				int x = range->start.col - 1;
				int y = range->start.line - top_line;
				if (column_offset <= x) {
					tb_printf(
						x - column_offset, y,
						foreground, background,
						"%.*s", str_len, str
					);
				} else if (x + str_len >= column_offset) {
					tb_printf(
						0, y,
						foreground, background,
						"%.*s",
						str_len - (column_offset - x),
						str + (column_offset - x)
					);
				}
			}
		}

		if (focused_symbol != NULL) {
			const buxn_asm_source_region_t* region = &focused_symbol->region;
			buxn_tui_status_line(
				"%s (%d:%d:%d - %d:%d:%d)",
				region->filename,
				region->range.start.line, region->range.start.col, region->range.start.byte,
				region->range.end.line, region->range.end.col, region->range.end.byte
			);
		} else {
			buxn_tui_status_line("No source");
		}

		bio_tb_present();

		const buxn_dbg_sym_t* old_focused_symbol = focused_symbol;
		buxn_tui_loop(msg, mailbox) {
			switch (buxn_tui_handle_event(&msg)) {
				case BUXN_TUI_MOVE_LEFT:
					if (focused_symbol != NULL) {
						// Search backward in the symbol table for:
						//
						// * A symbol in the same file
						// * Has a start byte before the focused address
						// * Has a start address before the focused address
						int sym_index = (int)(focused_symbol - ctx->symtab->symbols);
						for (int i = sym_index - 1; i >= 0; --i) {
							const buxn_dbg_sym_t* symbol = &ctx->symtab->symbols[i];
							if (
								symbol->region.filename == focused_symbol->region.filename
								&& symbol->region.range.start.byte < focused_symbol->region.range.start.byte
								&& symbol->addr_min < ctx->focus_address
							) {
								focused_symbol = symbol;
								break;
							}
						}
					}
					break;
				case BUXN_TUI_MOVE_RIGHT:
					if (focused_symbol != NULL) {
						// Search forward in the symbol table for:
						//
						// * A symbol in the same file
						// * Has a start byte after the focused address
						// * Has a start address after the focused address
						int sym_index = (int)(focused_symbol - ctx->symtab->symbols);
						for (int i = sym_index + 1; i < ctx->symtab->num_symbols; ++i) {
							const buxn_dbg_sym_t* symbol = &ctx->symtab->symbols[i];
							if (
								symbol->region.filename == focused_symbol->region.filename
								&& symbol->region.range.start.byte > focused_symbol->region.range.start.byte
								&& symbol->addr_min > ctx->focus_address
							) {
								focused_symbol = symbol;
								break;
							}
						}
					}
					break;
				case BUXN_TUI_MOVE_UP:
					if (focused_symbol != NULL && source.lines != NULL) {
						buxn_asm_file_range_t sym_range = focused_symbol->region.range;
						int sym_lineno = sym_range.start.line;

						// Search upward in lines for a line with at least a
						// symbol whose address is before the focused address
						source_line_t* line = NULL;
						for (int i = sym_lineno - 1; i >= 1; --i) {
							source_line_t* candidate_line = &source.lines[i - 1];
							for (int j = 0; j < (int)barray_len(candidate_line->symbols); ++j) {
								if (candidate_line->symbols[j]->addr_min < ctx->focus_address) {
									line = candidate_line;
									break;
								}
							}

							if (line != NULL) { break; }
						}

						// Search within this line for a symbol whose column is
						// the closest to the focused symbol and with a lower
						// start address
						const buxn_dbg_sym_t* next_sym = NULL;
						if (line != NULL) {
							int col_diff = INT_MAX;
							for (int i = 0; i < (int)barray_len(line->symbols); ++i) {
								const buxn_dbg_sym_t* candidate_sym = line->symbols[i];
								if (candidate_sym->addr_min >= focused_symbol->addr_min) {
									continue;
								}

								int candidate_col_diff = abs(
									candidate_sym->region.range.start.col - sym_range.start.col
								);
								if (candidate_col_diff < col_diff) {
									next_sym = candidate_sym;
									col_diff = candidate_col_diff;
								}
							}
						}

						if (next_sym != NULL) {
							focused_symbol = next_sym;
						}
					}
					break;
				case BUXN_TUI_MOVE_DOWN:
					if (focused_symbol != NULL) {
						buxn_asm_file_range_t sym_range = focused_symbol->region.range;
						int sym_lineno = sym_range.start.line;

						// Search downward in lines for a line with at least a
						// symbol whose start address is after the focused address
						source_line_t* line = NULL;
						for (int i = sym_lineno + 1; i <= (int)barray_len(source.lines); ++i) {
							source_line_t* candidate_line = &source.lines[i - 1];
							for (int j = 0; j < (int)barray_len(candidate_line->symbols); ++j) {
								if (candidate_line->symbols[j]->addr_min > ctx->focus_address) {
									line = candidate_line;
									break;
								}
							}

							if (line != NULL) { break; }
						}

						// Search within this line for a symbol whose column is
						// the closest to the focused symbol and with a higher
						// start address
						const buxn_dbg_sym_t* next_sym = NULL;
						if (line != NULL) {
							int col_diff = INT_MAX;
							for (int i = 0; i < (int)barray_len(line->symbols); ++i) {
								const buxn_dbg_sym_t* candidate_sym = line->symbols[i];
								if (candidate_sym->addr_min <= focused_symbol->addr_min) {
									continue;
								}
								int candidate_col_diff = abs(
									candidate_sym->region.range.start.col - sym_range.start.col
								);
								if (candidate_col_diff < col_diff) {
									next_sym = candidate_sym;
									col_diff = candidate_col_diff;
								}
							}
						}

						if (next_sym != NULL) {
							focused_symbol = next_sym;
						}
					}
					break;
				case BUXN_TUI_MOVE_TO_LINE_START:
					if (focused_symbol != NULL && source.lines != NULL) {
						buxn_asm_file_range_t sym_range = focused_symbol->region.range;
						int sym_lineno = sym_range.start.line;
						barray(const buxn_dbg_sym_t*) line_syms = source.lines[sym_lineno - 1].symbols;
						focused_symbol = line_syms[0];
					}
					break;
				case BUXN_TUI_MOVE_TO_LINE_END:
					if (focused_symbol != NULL && source.lines != NULL) {
						buxn_asm_file_range_t sym_range = focused_symbol->region.range;
						int sym_lineno = sym_range.start.line;
						barray(const buxn_dbg_sym_t*) line_syms = source.lines[sym_lineno - 1].symbols;
						focused_symbol = line_syms[barray_len(line_syms) - 1];
					}
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

		if (focused_symbol != old_focused_symbol) {
			ctx->focus_address = focused_symbol->addr_min;
			buxn_dbg_client_set_focus(ctx->client, focused_symbol->addr_min);
		}
	}

	bio_wait_and_send_message(true, ctx->main_mailbox, (msg_t){ .type = MSG_QUIT });
}

static bool
load_file(const char* path, source_t* source, bio_error_t* error) {
	bio_file_t file = { 0 };
	bool loaded = false;
	if (!bio_fopen(&file, path, "r", error)) {
		goto end;
	}

	bio_stat_t stat = { 0 };
	if (!bio_fstat(file, &stat, error)) {
		goto end;
	}

	char* content = buxn_dbg_malloc(stat.size);
	if (bio_fread(file, content, stat.size, error) != stat.size) {
		buxn_dbg_free(content);
		goto end;
	}
	source->content = content;
	source->size = (int)stat.size;

	loaded = true;
end:
	bio_fclose(file, NULL);
	return loaded;
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
			.client_name = "view:source",
			.subscriptions = BUXN_DBGX_SUB_INFO_PUSH | BUXN_DBGX_SUB_FOCUS,
			.options = BUXN_DBGX_INIT_OPT_INFO | BUXN_DBGX_INIT_OPT_CONFIG,
		},
		&(buxn_dbgx_init_rep_t){
			.info = &info,
			.config = &config,
		}
	)) {
		return 1;
	}

	buxn_dbg_symtab_t* symtab = NULL;
	if (config.dbg_filename != NULL && config.src_dir != NULL) {
		symtab = buxn_dbg_load_symbols(config.dbg_filename);
	}
	if (symtab == NULL) {
		BIO_ERROR("Could not load debug file");
		return 1;
	}

	buxn_dbg_set_logger(buxn_dbg_add_net_logger(BIO_LOG_LEVEL_TRACE, "view:source"));

	source_set_t source_set;
	bhash_config_t hash_cfg = bhash_config_default();
	hash_cfg.removable = false;
	bhash_init(&source_set, hash_cfg);

	tui_ctx_t ui_ctx = {
		.main_mailbox = mailbox,
		.client = client,
		.symtab = symtab,
		.source_set = &source_set,
		.focus_address = info.focus,
		.pc = info.pc,
	};
	buxn_tui_t tui = buxn_tui_start(tui_entry, &ui_ctx);

	char path_buf[1024];  // TODO: dynamically allocate
	bio_foreach_message(msg, mailbox) {
		switch (msg.type) {
			case MSG_LOAD_SOURCE: {
				// Put in a dummy entry so UI coro stops bothering us
				source_t src = { 0 };
				bhash_put(&source_set, msg.load_source.name, src);

				int len = snprintf(
					path_buf, sizeof(path_buf),
					"%s/%s",
					config.src_dir, msg.load_source.name
				);
				if (len < 0 || len >= (int)sizeof(path_buf)) {
					BIO_ERROR("Invalid source path");
					continue;
				}

				BIO_TRACE("Loading %s", path_buf);
				bio_error_t error = { 0 };
				if (!load_file(path_buf, &src, &error)) {
					BIO_ERROR(
						"Error while loading %s: " BIO_ERROR_FMT,
						path_buf, BIO_ERROR_FMT_ARGS(&error)
					);
					continue;
				}

				// Replace tab with space since we can't render it
				for (int i = 0; i < src.size; ++i) {
					if (src.content[i] == '\t') {
						src.content[i] = ' ';
					}
				}

				// Parse into lines
				source_line_t current_line = {
					.content = src.content,
					.len = 0,
				};
				int start_index = 0;
				for (int i = 0; i < src.size; ++i) {
					char ch = src.content[i];
					if (ch == '\n') {
						current_line.len = i - start_index;
						barray_push(src.lines, current_line, NULL);
						current_line.content = src.content + i + 1;
						start_index = i + 1;
					} else if (ch == '\r') {
						if (i < src.size - 1 && src.content[i + 1] == '\n') {
							current_line.len = i - start_index;
							barray_push(src.lines, current_line, NULL);
							current_line.content = src.content + i + 2;
							start_index = i + 2;
						} else {
							current_line.len = i - start_index;
							barray_push(src.lines, current_line, NULL);
							current_line.content = src.content + i + 1;
							start_index = i + 1;
						}
					}
				}
				// Last line
				if (start_index < src.size) {
					current_line.len = src.size - start_index;
					barray_push(src.lines, current_line, NULL);
				}

				// Index all symbols to line
				int num_lines = barray_len(src.lines);
				for (int i = 0; i < symtab->num_symbols; ++i) {
					const buxn_dbg_sym_t* symbol = &symtab->symbols[i];
					int symbol_line = symbol->region.range.start.line;
					if (
						symbol->region.filename == msg.load_source.name
						&& symbol_line <= num_lines
					) {
						source_line_t* line = &src.lines[symbol_line - 1];
						barray_push(line->symbols, symbol, NULL);
					}
				}

				// Commit
				bhash_put(&source_set, msg.load_source.name, src);
				buxn_tui_refresh(tui);
			} break;
			case MSG_SET_FOCUS:
				ui_ctx.focus_address = msg.set_focus.address;
				buxn_tui_refresh(tui);
				break;
			case MSG_INFO_PUSH:
				ui_ctx.focus_address = msg.info_push.focus;
				ui_ctx.pc = msg.info_push.pc;
				buxn_tui_refresh(tui);
				break;
			case MSG_QUIT:
				goto end;
		}
	}
end:

	buxn_tui_stop(tui);

	bhash_index_t num_sources = bhash_len(&source_set);
	for (bhash_index_t i = 0; i < num_sources; ++i) {
		source_t* source = &source_set.values[i];
		for (int i = 0; i < (int)barray_len(source->lines); ++i) {
			barray_free(NULL, source->lines[i].symbols);
		}
		barray_free(NULL, source->lines);
		buxn_dbg_free(source->content);
	}
	bhash_cleanup(&source_set);

	bio_close_mailbox(mailbox);
	buxn_dbg_stop_client(client);
	buxn_dbg_unload_symbols(symtab);

	return 0;
}

BUXN_DBG_CMD_EX(view_source, "view:source", "View the current source file") {
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
		.usage = "buxn-dbg view:source [options]",
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
