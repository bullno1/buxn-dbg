#include "client.h"
#include <bserial.h>

static const bio_tag_t BUXN_CLIENT_DATA = BIO_TAG_INIT("buxn.client.data");

typedef enum {
	CLIENT_MSG_READER_TERMINATED,
	CLIENT_MSG_SEND,
} msg_type_t;

struct buxn_dbg_client_handler_msg_s {
	msg_type_t type;

	buxn_dbgx_msg_t msg;
};

typedef BIO_MAILBOX(buxn_dbg_client_handler_msg_t) mailbox_t;

typedef struct {
	bserial_ctx_t* bserial_in;
	buxn_dbg_client_controller_t* controller;
	mailbox_t service_mailbox;
	bool should_terminate;
} reader_ctx_t;

static void
reader_entry(void* userdata) {
	reader_ctx_t* ctx = userdata;
	buxn_dbg_msg_buffer_t msg_buf;

	while (!ctx->should_terminate) {
		buxn_dbgx_msg_t msg;
		if (!buxn_dbgx_protocol_msg(ctx->bserial_in, msg_buf, &msg)) {
			if (bio_is_mailbox_open(ctx->service_mailbox) && !ctx->should_terminate) {
				BIO_ERROR("Error while reading message from client");
			}
			break;
		}

		buxn_dbg_client_request(ctx->controller, msg);
	}

	buxn_dbg_client_handler_msg_t term_msg = {
		.type = CLIENT_MSG_READER_TERMINATED,
	};
	bio_wait_and_send_message(
		!ctx->should_terminate,
		ctx->service_mailbox,
		term_msg
	);
}

static void
handler_entry(void* userdata) {
	buxn_dbg_client_args_t args;
	mailbox_t mailbox;
	bio_get_service_info(userdata, &mailbox, &args);
	bio_set_coro_data(&args, &BUXN_CLIENT_DATA);

	bserial_ctx_config_t bserial_cfg = {
		.max_num_symbols = 16,
		.max_record_fields = 8,
		.max_symbol_len = 16,
		.max_depth = 4,
	};
	size_t bserial_mem_size = bserial_ctx_mem_size(bserial_cfg);
	void* bserial_mem_in = buxn_dbg_malloc(bserial_mem_size);
	void* bserial_mem_out = buxn_dbg_malloc(bserial_mem_size);
	bserial_ctx_t* bserial_in = bserial_make_ctx(bserial_mem_in, bserial_cfg, &args.io.in, NULL);
	bserial_ctx_t* bserial_out = bserial_make_ctx(bserial_mem_out, bserial_cfg, NULL, &args.io.out);

	reader_ctx_t reader_ctx = {
		.bserial_in = bserial_in,
		.service_mailbox = mailbox,
	};
	bio_coro_t reader_coro = bio_spawn(reader_entry, &reader_ctx);

	bio_foreach_message(msg, mailbox) {
		switch (msg.type) {
			case CLIENT_MSG_READER_TERMINATED:
				goto end;
			case CLIENT_MSG_SEND:
				if (!buxn_dbgx_protocol_msg(bserial_out, NULL, &msg.msg)) {
					if (bio_is_mailbox_open(mailbox)) {
						BIO_ERROR("Error while sending message to client");
					}
					break;
				}
				break;
		}
	}
end:
	bio_net_close(args.io.socket, NULL);
	reader_ctx.should_terminate = true;
	bio_join(reader_coro);

	buxn_dbg_free(bserial_mem_out);
	buxn_dbg_free(bserial_mem_in);

	buxn_dbg_client_terminated(args.controller);
}

buxn_dbg_client_handler_t
buxn_dbg_start_client_handler(const buxn_dbg_client_args_t* args) {
	buxn_dbg_client_handler_t handler;
	bio_start_service(&handler, handler_entry, *args, 4);
	return handler;
}

void
buxn_dbg_stop_client_handler(buxn_dbg_client_handler_t client) {
	buxn_dbg_client_args_t* args = bio_get_coro_data(client.coro, &BUXN_CLIENT_DATA);
	if (args != NULL) {
		bio_net_close(args->io.socket, NULL);
		bio_stop_service(client);
	}
}

bool
buxn_dbg_notify_client(buxn_dbg_client_handler_t client, buxn_dbgx_msg_t msg) {
	buxn_dbg_client_handler_msg_t msg_to_client = {
		.type = CLIENT_MSG_SEND,
		.msg = msg,
	};
	return bio_send_message(client.mailbox, msg_to_client);
}
