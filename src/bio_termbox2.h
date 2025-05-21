#ifndef BIO_TERMBOX2_H
#define BIO_TERMBOX2_H

#include <termbox2.h>
#include <stdbool.h>

// Wrapper for termbox2 to make it run in an async thread.
// Most functions are OK to use since it buffers all output until tb_present.
// And even when they block, it shouldn't be long.
// Only the event handling ones are the most problematic since they can block
// indefinitely.
// TODO: Replace its implementation instead.

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

#endif
