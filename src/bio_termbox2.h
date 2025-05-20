#include <termbox2.h>
#include <stdbool.h>

// Wrapper for termbox2 to make it run in an async thread.
// Most functions are OK to use since it buffers all output until tb_present.
// And even when they block, it shouldn't be long.
// Only the event handling ones are the most problematic since they can block
// indefinitely.
// TODO: Replace its implementation instead.

/**
 * Event loop helper for a "UI application".
 *
 * A typical loop would be like:
 *
 * ```c
 * while (should_run) {
 *     render_ui();
 *     bio_tb_present();
 *
 *     bio_tb_foreach_message(msg, mailbox) {
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
#define bio_tb_foreach_message(MSG, MAILBOX) \
	/* First, we use a for loop to declare some local variables. */ \
	/* Due to bio_tb__loop_vars.i the top level for loop will only be run once. */ \
	for ( \
		struct {  \
			int i; \
			int j; \
			bool received; \
		} bio_tb__loop_vars = { .i = 0, .j = 0 }; \
		bio_tb__loop_vars.i < 1; \
		++bio_tb__loop_vars.i \
	) \
		/* Then, we declare the requested variable. */ \
		/* This is another single iteration loop guarded with bio_tb__loop_vars.j */ \
		for ( \
			BIO__TYPEOF(*(MAILBOX).bio__message) MSG; \
			bio_tb__loop_vars.j < 1; \
			++bio_tb__loop_vars.j \
		) \
			/* Finally, we create the actual message loop. */ \
			/* On initialization, bio_recv_message blocks until a message is available. */ \
			/* On subsequent iterations, it checks using bio_can_recv_message before receiving. */ \
			for ( \
				bio_tb__loop_vars.received = bio_recv_message((MAILBOX), &(MSG)); \
				bio_tb__loop_vars.received; \
				bio_tb__loop_vars.received = \
					bio_can_recv_message(MAILBOX) \
					&& bio_recv_message(MAILBOX, &(MSG)) \
			) \


typedef struct {
	void* userdata;
	void (*event_callback)(void* userdata, const struct tb_event* event);
} bio_tb_options_t;

int
bio_tb_init(const bio_tb_options_t* options);

int
bio_tb_shutdown(void);

bool
bio_tb_is_running(void);

int
bio_tb_present(void);
