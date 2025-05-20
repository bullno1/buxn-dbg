#include "bio_termbox2.h"
#include <bio/bio.h>

typedef struct {
	bio_tb_options_t options;
	bio_coro_t coro;
	bio_signal_t ready_sig;
	bool should_terminate;
} bio_tb_ctx_t;

static bio_tb_ctx_t bio_tb_ctx = { 0 };

typedef struct {
	int result;
	int (*fn)(void);
} bio_tb_void_wrapper_ctx_t;

typedef struct {
	int result;
	int timeout_ms;
	struct tb_event* event;
} bio_tb_peek_event_ctx_t;

static void
bio_tb_void_wrapper(void* userdata) {
	bio_tb_void_wrapper_ctx_t* ctx = userdata;
	ctx->result = ctx->fn();
}

static void
bio_tb_peek_event_wrapper(void* userdata) {
	bio_tb_peek_event_ctx_t* ctx = userdata;
	ctx->result = tb_peek_event(ctx->event, ctx->timeout_ms);
}

static int
bio_tb_peek_event(struct tb_event* event, int timeout_ms) {
	bio_tb_peek_event_ctx_t peek_ctx = {
		.event = event,
		.timeout_ms = timeout_ms,
	};
	bio_run_async_and_wait(bio_tb_peek_event_wrapper, &peek_ctx);
	return peek_ctx.result;
}

static void
bio_tb_event_poller(void* userdata) {
	bio_tb_ctx_t* ctx = userdata;
	bio_raise_signal(ctx->ready_sig);
	BIO_DEBUG("termbox poller started");

	struct tb_event event_buf[8];
	int event_buf_len = sizeof(event_buf) / sizeof(event_buf[0]);

	while (!ctx->should_terminate) {
		int num_events = 0;
		int poll_result = bio_tb_peek_event(&event_buf[num_events], -1);
		if (poll_result != TB_OK) { bio_yield(); }

		while (poll_result == TB_OK && num_events < event_buf_len - 1) {
			++num_events;
			poll_result = bio_tb_peek_event(&event_buf[num_events], 0);
		}
		if (poll_result == TB_OK) { ++num_events; }

		for (int i = 0; i < num_events; ++i) {
			ctx->options.event_callback(ctx->options.userdata, &event_buf[i]);
		}
	}

	BIO_DEBUG("termbox poller terminated");
}

int
bio_tb_init(const bio_tb_options_t* options) {
	if (bio_tb_is_running()) { return TB_ERR_INIT_ALREADY; }

	bio_tb_void_wrapper_ctx_t ctx = { .fn = tb_init };
	bio_run_async_and_wait(bio_tb_void_wrapper, &ctx);

	if (ctx.result != TB_OK) {
		return ctx.result;
	}

	bio_tb_ctx = (bio_tb_ctx_t){
		.options = *options,
		.ready_sig = bio_make_signal(),
	};
	bio_tb_ctx.coro = bio_spawn(bio_tb_event_poller, &bio_tb_ctx);
	bio_wait_for_one_signal(bio_tb_ctx.ready_sig);

	return TB_OK;
}

int
bio_tb_shutdown(void) {
	if (!bio_tb_is_running()) { return TB_ERR_NOT_INIT; }

	bio_tb_ctx.should_terminate = true;

	// This should interrupt the poll
	bio_tb_void_wrapper_ctx_t ctx = { .fn = tb_shutdown };
	bio_run_async_and_wait(bio_tb_void_wrapper, &ctx);

	bio_join(bio_tb_ctx.coro);

	return ctx.result;
}

bool
bio_tb_is_running(void) {
	return (
		!bio_tb_ctx.should_terminate
		&& bio_coro_state(bio_tb_ctx.coro) != BIO_CORO_DEAD
	);
}

int
bio_tb_present(void) {
	bio_tb_void_wrapper_ctx_t ctx = { .fn = tb_present };
	bio_run_async_and_wait(bio_tb_void_wrapper, &ctx);
	return ctx.result;
}

#define TB_IMPL
#include <termbox2.h>
