#include "tui.h"
#include "client.h"

typedef struct {
	buxn_tui_entrypoint_t entrypoint;
	void* userdata;
} buxn_tui_args_t;

static void
buxn_tui_bio_tb_callback(void* userdata, const struct tb_event* event) {
	buxn_tui_mailbox_t mailbox = *(buxn_tui_mailbox_t*)userdata;
	struct tb_event ev = *event;
	bio_wait_and_send_message(bio_tb_is_running(), mailbox, ev);
}

static void
buxn_tui_wrapper(void* userdata) {
	buxn_tui_args_t args;
	buxn_tui_mailbox_t mailbox;
	bio_get_service_info(userdata, &mailbox, &args);
	bio_set_coro_name("tui");

	bio_tb_init(&(bio_tb_options_t){
		.userdata = &mailbox,
		.event_callback = buxn_tui_bio_tb_callback,
	});

	args.entrypoint(mailbox, args.userdata);

	bio_tb_shutdown();
	bio_close_mailbox(mailbox);
}

buxn_tui_t
buxn_tui_start(buxn_tui_entrypoint_t entrypoint, void* userdata) {
	buxn_tui_t tui;
	buxn_tui_args_t args = {
		.entrypoint = entrypoint,
		.userdata = userdata,
	};
	bio_start_service(&tui, buxn_tui_wrapper, args, 4);
	return tui;
}

void
buxn_tui_stop(buxn_tui_t ui) {
	bio_stop_service(ui);
}

void
buxn_tui_refresh(buxn_tui_t ui) {
	struct tb_event event = { 0 };
	bio_wait_and_send_message(true, ui.mailbox, event);
}

buxn_tui_event_type_t
buxn_tui_handle_event(const struct tb_event* event) {
	if (event->type == 0) {
		return BUXN_TUI_REFRESH;
	} else if (event->type == TB_EVENT_KEY) {
		if (
			event->key == TB_KEY_CTRL_C
			|| event->key == TB_KEY_ESC
			|| event->ch == 'q'
		) {
			return BUXN_TUI_QUIT;
		} else if (
			event->key == TB_KEY_ARROW_RIGHT
			|| event->ch == 'l'
		) {
			return BUXN_TUI_MOVE_RIGHT;
		} else if (
			event->key == TB_KEY_ARROW_LEFT
			|| event->ch == 'h'
		) {
			return BUXN_TUI_MOVE_LEFT;
		} else if (
			event->key == TB_KEY_ARROW_UP
			|| event->ch == 'k'
		) {
			return BUXN_TUI_MOVE_UP;
		} else if (
			event->key == TB_KEY_ARROW_DOWN
			|| event->ch == 'j'
		) {
			return BUXN_TUI_MOVE_DOWN;
		} else if (
			event->key == TB_KEY_HOME
			|| event->ch == '0'
		) {
			return BUXN_TUI_MOVE_TO_LINE_START;
		} else if (
			event->key == TB_KEY_END
			|| event->ch == '$'
		) {
			return BUXN_TUI_MOVE_TO_LINE_END;
		} else if (event->ch == 's') {
			return BUXN_TUI_STEP;
		} else if (event->ch == 'n') {
			return BUXN_TUI_STEP;
		} else if (event->ch == 'r') {
			return BUXN_TUI_STEP;
		} else {
			return BUXN_TUI_UNKNOWN;
		}
	} else {
		return BUXN_TUI_UNKNOWN;
	}
}

bio_call_status_t
buxn_tui_execute_step(const struct tb_event* event, buxn_dbg_client_t client) {
	bool do_step = false;
	buxn_dbg_cmd_type_t step = BUXN_DBG_CMD_STEP_IN;
	if (event->type == TB_EVENT_KEY) {
		// Control following pdb convention
		if (event->ch == 's') {  // (s)tep (in)
			step = BUXN_DBG_CMD_STEP_IN;
			do_step = true;
		} else if (event->ch == 'n') {  // (n)ext (step over)
			step = BUXN_DBG_CMD_STEP_OVER;
			do_step = true;
		} else if (event->ch == 'r') {  // (r)eturn (step out)
			step = BUXN_DBG_CMD_STEP_OUT;
			do_step = true;
		}
	}

	if (do_step) {
		return buxn_dbg_client_send_dbg_cmd(client, (buxn_dbg_cmd_t){
			.type = step,
		});
	} else {
		return BIO_CALL_OK;
	}
}

void
buxn_tui_status_line(const char* fmt, ...) {
    char buf[1024];
	va_list args;
	va_start(args, fmt);
    int rv = vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);
    if (rv < 0 || rv >= (int)sizeof(buf)) {
		return;
	}
	int width = tb_width();
	int height = tb_height();
	size_t num_chars;
	tb_print_ex(0, height - 1, TB_BLACK, TB_WHITE, &num_chars, buf);
	if ((int)num_chars < width) {
		tb_printf((int)num_chars, height - 1, TB_BLACK, TB_WHITE, "%*s", width - num_chars, "");
	}
}
