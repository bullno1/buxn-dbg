#include "tui.h"

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
	bio_send_message(ui.mailbox, event);
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
		} else {
			return BUXN_TUI_UNKNOWN;
		}
	} else {
		return BUXN_TUI_UNKNOWN;
	}
}
