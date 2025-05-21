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
	const char* dbg_filename;
	const char* src_dir;
} args_t;

typedef struct {
	const char* content;
	int len;
} source_line_t;

typedef struct {
	char* content;
	int size;
	barray(source_line_t) lines;
} source_t;

typedef BHASH_TABLE(const char*, source_t) source_set_t;

typedef enum {
	MSG_LOAD_SOURCE,
	MSG_QUIT,
} msg_type_t;

typedef struct {
	msg_type_t type;

	union {
		struct {
			const char* name;
		} load_source;
	};
} msg_t;

typedef BIO_MAILBOX(msg_t) mailbox_t;

typedef struct {
	mailbox_t main_mailbox;
	const buxn_dbg_symtab_t* symtab;
	source_set_t* source_set;
} tui_ctx_t;

static void
tui_entry(buxn_tui_mailbox_t mailbox, void* userdata) {
	tui_ctx_t* ctx = userdata;

	const buxn_dbg_sym_t* focused_symbol = buxn_dbg_find_symbol(ctx->symtab, 0x0100, NULL);
	int top_line = 1;
	/*int left_column = 1;*/
	int focus_line = 1;
	/*int focus_column = 1;*/

	bool should_run = true;
	while (bio_is_mailbox_open(mailbox) && should_run) {
		tb_clear();

		/*int width = tb_width();*/
		int height = tb_height();

		const char* focused_filename = focused_symbol->region.filename;
		bhash_index_t index = bhash_find(ctx->source_set, focused_filename);
		source_t source = { 0 };
		if (!bhash_is_valid(index)) {
			// Ask main to load it
			msg_t msg = {
				.type = MSG_LOAD_SOURCE,
				.load_source.name = focused_filename,
			};
			bio_wait_and_send_message(true, ctx->main_mailbox, msg);
		} else {
			source = ctx->source_set->values[index];
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
		int symbol_index = 0;
		for (int line = top_line; line <= bottom_line; ++line) {
			if (line > num_lines) { break; }

			const source_line_t* source_line = &source.lines[line - 1];
			tb_printf(
				0, line - top_line,
				TB_DEFAULT, TB_DEFAULT,
				"%.*s",
				source_line->len, source_line->content
			);

			// Semantic highlighting by drawing over the current line
			// TODO: for multi byte symbols (e.g: #02), we over draw the same
			// cell multiple times.
			// This could be slow
			for (; symbol_index < ctx->symtab->num_symbols; ++symbol_index) {
				const buxn_dbg_sym_t* symbol = &ctx->symtab->symbols[symbol_index];
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

				int x = range->start.col - 1;
				int y = range->start.line - top_line;
				tb_printf(
					x, y,
					foreground, background,
					"%.*s", str_len, str
				);
			}
		}

		if (focused_symbol != NULL) {
			buxn_tui_status_line("%s", focused_symbol->region.filename);
		}

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

static int
bio_main(void* userdata) {
	args_t* args = userdata;

	buxn_dbg_symtab_t* symtab = NULL;
	if (args->dbg_filename != NULL) {
		symtab = buxn_dbg_load_symbols(args->dbg_filename);
	}
	if (symtab == NULL) {
		return 1;
	}

	buxn_dbg_client_t client;
	if (!buxn_dbg_make_client(
		&client,
		&args->connect_transport,
		&(buxn_dbgx_init_t){ .client_name = "view:source" }
	)) {
		return 1;
	}
	buxn_dbg_set_logger(buxn_dbg_add_net_logger(BIO_LOG_LEVEL_TRACE, client));

	mailbox_t mailbox;
	bio_open_mailbox(&mailbox, 8);

	source_set_t source_set;
	bhash_config_t hash_cfg = bhash_config_default();
	hash_cfg.removable = false;
	bhash_init(&source_set, hash_cfg);

	tui_ctx_t ui_ctx = {
		.main_mailbox = mailbox,
		.symtab = symtab,
		.source_set = &source_set,
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
					"%s%s",
					args->src_dir, msg.load_source.name
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

				// Commit
				bhash_put(&source_set, msg.load_source.name, src);
				buxn_tui_refresh(tui);
			} break;
			case MSG_QUIT:
				goto end;
		}
	}
end:

	buxn_tui_stop(tui);

	bhash_index_t num_sources = bhash_len(&source_set);
	for (bhash_index_t i = 0; i < num_sources; ++i) {
		barray_free(NULL, source_set.values[i].lines);
	}
	bhash_cleanup(&source_set);

	bio_close_mailbox(mailbox);
	buxn_dbg_stop_client(client);
	buxn_dbg_unload_symbols(symtab);

	return 0;
}

BUXN_DBG_CMD_EX(view_source, "view:source", "View the source file") {
	args_t args = {
		.src_dir = "./",
	};
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
		},
		{
			.name = "src-dir",
			.short_name = 's',
			.value_name = "path",
			.parser = barg_str(&args.src_dir),
			.summary = "The base directory to load sources from",
			.description =
				"Defaults to the current directory",
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
