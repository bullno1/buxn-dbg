#include "cmd.h"
#include "common.h"
#include "logger.h"
#include <bio/net.h>

typedef struct {
	bio_socket_t sock;
	bio_signal_t ready_sig;
} client_ctx_t;

static void
client_entry(void* userdata) {
	client_ctx_t ctx = *(client_ctx_t*)userdata;
	bio_raise_signal(ctx.ready_sig);

	bserial_socket_io_t io;
	bserial_socket_io_init(&io, ctx.sock);
	void* bserial_mem = buxn_dbg_malloc(bserial_ctx_mem_size(buxn_log_bserial_config));
	bserial_ctx_t* bserial_in = bserial_make_ctx(bserial_mem, buxn_log_bserial_config, &io.in, NULL);

	// Receive name
	bool should_run = false;
	char name_buf[64];
	{
		btmp_buf_t tmp_buf = { .mem = name_buf, .size = sizeof(name_buf) };
		const char* name = NULL;
		if (bserial_str(bserial_in, &name, &tmp_buf) == BSERIAL_OK) {
			if (name != NULL) { bio_set_coro_name(name); }
			should_run = true;
		}
	}

	while (should_run) {
		char msg_buf[1024];
		buxn_dbg_log_msg_t msg = { 0 };
		btmp_buf_t tmp_buf = { .mem = msg_buf, .size = sizeof(msg_buf) };
		if (buxn_dbg_serialize_log_msg(bserial_in, &msg, &tmp_buf) != BSERIAL_OK) {
			break;
		}

		if (msg.coro != NULL) {
			bio_log(
				msg.level, msg.file, msg.line,
				"<%s>: %s", msg.coro, msg.content
			);
		} else {
			bio_log(
				msg.level, msg.file, msg.line,
				"<%d:%d>: %s", ctx.sock.handle.index, ctx.sock.handle.gen, msg.content
			);
		}
	}

	buxn_dbg_free(bserial_mem);
	bio_net_close(ctx.sock, NULL);
}

static int
bio_main(void* userdata) {
	bio_socket_t server_sock;
	bio_error_t error = { 0 };
	bio_addr_t addr = {
		.type = BIO_ADDR_NAMED,
		.named = {
			.len = sizeof(BUXN_DBG_LOG_SOCKET) - 1,
			.name = BUXN_DBG_LOG_SOCKET,
		},
	};
	if (!bio_net_listen(BIO_SOCKET_STREAM, &addr, BIO_PORT_ANY, &server_sock, &error)) {
		BIO_FATAL("Could not create listening socket: " BIO_ERROR_FMT, BIO_ERROR_FMT_ARGS(&error));
		return 1;
	}

	while (true) {
		client_ctx_t client_ctx = { 0 };
		if (!bio_net_accept(server_sock, &client_ctx.sock, &error)) {
			BIO_FATAL("Error while accepting: " BIO_ERROR_FMT, BIO_ERROR_FMT_ARGS(&error));
			break;
		}

		client_ctx.ready_sig = bio_make_signal();
		bio_spawn(client_entry, &client_ctx);
		bio_wait_for_one_signal(client_ctx.ready_sig);
	}

	bio_net_close(server_sock, NULL);

	return 0;
}

BUXN_DBG_CMD_EX(dev_logd, "dev:logd", "Remote log server") {
	return bio_enter(bio_main, NULL);
}
