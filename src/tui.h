#ifndef BUXN_TUI_H
#define BUXN_TUI_H

#include "bio_termbox2.h"
#include <bio/mailbox.h>
#include <bio/service.h>

/**
 * Event loop helper for a "UI application".
 *
 * A typical loop would be like:
 *
 * ```c
 * while (should_run) {
 *     render_ui();
 *     buxn_tui_present();
 *
 *     buxn_tui_loop(msg, mailbox) {
 *         switch (msg.type) {
 *         }
 *     }
 * }
 * ```
 *
 * This macro enforces the following behaviour:
 *
 * * (Async) block for at least one message on mailbox.
 * * Subsequently, immediately bail out of the loop if the mailbox is empty.
 *
 * This allows the application to rerender when there is no pending event.
 * `bio_foreach_message`, on the other hand, will always block unil the mailbox
 * is closed.
 */
#define buxn_tui_loop(MSG, MAILBOX) \
	/* First, we use a for loop to declare some local variables. */ \
	/* Due to buxn_tui__loop_vars.i the top level for loop will only be run once. */ \
	for ( \
		struct {  \
			int i; \
			int j; \
			bool received; \
		} buxn_tui__loop_vars = { .i = 0, .j = 0 }; \
		buxn_tui__loop_vars.i < 1; \
		++buxn_tui__loop_vars.i \
	) \
		/* Then, we declare the requested variable. */ \
		/* This is another single iteration loop guarded with buxn_tui__loop_vars.j */ \
		for ( \
			BIO__TYPEOF(*(MAILBOX).bio__message) MSG; \
			buxn_tui__loop_vars.j < 1; \
			++buxn_tui__loop_vars.j \
		) \
			/* Finally, we create the actual message loop. */ \
			/* On initialization, bio_recv_message blocks until a message is available. */ \
			/* On subsequent iterations, it checks using bio_can_recv_message before receiving. */ \
			for ( \
				buxn_tui__loop_vars.received = bio_recv_message((MAILBOX), &(MSG)); \
				buxn_tui__loop_vars.received; \
				buxn_tui__loop_vars.received = \
					bio_can_recv_message(MAILBOX) \
					&& bio_recv_message(MAILBOX, &(MSG)) \
			) \

typedef BIO_MAILBOX(struct tb_event) buxn_tui_mailbox_t;

typedef BIO_SERVICE(struct tb_event) buxn_tui_t;

typedef void (*buxn_tui_entrypoint_t)(buxn_tui_mailbox_t mailbox, void* userdata);

// Universal key binding for all views

typedef enum {
	BUXN_TUI_UNKNOWN,
	BUXN_TUI_REFRESH,
	BUXN_TUI_QUIT,
	BUXN_TUI_MOVE_UP,
	BUXN_TUI_MOVE_DOWN,
	BUXN_TUI_MOVE_LEFT,
	BUXN_TUI_MOVE_RIGHT,
	BUXN_TUI_MOVE_TO_LINE_START,
	BUXN_TUI_MOVE_TO_LINE_END,
} buxn_tui_event_type_t;

buxn_tui_t
buxn_tui_start(buxn_tui_entrypoint_t entrypoint, void* userdata);

void
buxn_tui_stop(buxn_tui_t ui);

void
buxn_tui_refresh(buxn_tui_t ui);

buxn_tui_event_type_t
buxn_tui_handle_event(const struct tb_event* event);

#endif
