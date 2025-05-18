#include "client.h"
#include <barray.h>
#include <string.h>

static const bio_tag_t BUXN_CLIENT_DATA = BIO_TAG_INIT("buxn.client.data");

typedef enum {
	CLIENT_MSG_DISCONNECTED,
	CLIENT_MSG_SEND,
} client_msg_type_t;

struct buxn_dbg_client_msg_s {
	BIO_SERVICE_MSG

	client_msg_type_t type;
	buxn_dbgx_msg_t msg;
};

typedef BIO_MAILBOX(buxn_dbg_client_msg_t) buxn_dbg_client_mailbox_t;

typedef struct {
	buxn_dbg_client_args_t* args;
	bserial_ctx_t* bserial_in;
	buxn_dbg_client_mailbox_t service_mailbox;
	barray(buxn_dbg_client_msg_t) pending_cmds;
	bool should_terminate;
} client_reader_ctx_t;

static void
reader_entry(void* userdata) {
	client_reader_ctx_t* ctx = userdata;

	while (!ctx->should_terminate) {
		buxn_dbgx_msg_t server_msg;
		if (buxn_dbgx_protocol_msg_header(ctx->bserial_in, &server_msg) != BSERIAL_OK) {
			break;
		}

		if (server_msg.type == BUXN_DBGX_MSG_CORE) {
			if (buxn_dbg_protocol_msg_header(ctx->bserial_in, &server_msg.core) != BSERIAL_OK) {
				break;
			}

			if (server_msg.core.type == BUXN_DBG_MSG_COMMAND_REP) {
				size_t num_pending_cmds = barray_len(ctx->pending_cmds);
				if (num_pending_cmds == 0) { break; }

				buxn_dbg_client_msg_t cmd = ctx->pending_cmds[0];
				memmove(
					ctx->pending_cmds,
					ctx->pending_cmds + 1,
					sizeof(cmd) * (num_pending_cmds - 1)
				);
				barray_resize(ctx->pending_cmds, num_pending_cmds - 1, NULL);
				server_msg.core.cmd = cmd.msg.core.cmd;
				if (buxn_dbg_protocol_msg_body(ctx->bserial_in, NULL, &server_msg.core) != BSERIAL_OK) {
					break;
				}

				// TODO: handle cancellation
				bio_respond(cmd) { }
			} else {
				if (buxn_dbg_protocol_msg_body(ctx->bserial_in, NULL, &server_msg.core) != BSERIAL_OK) {
					break;
				}
				if (ctx->args->msg_handler != NULL) {
					ctx->args->msg_handler(server_msg, ctx->args->userdata);
				}
			}
		} else {
			if (buxn_dbgx_protocol_msg_body(ctx->bserial_in, NULL, &server_msg) != BSERIAL_OK) {
				break;
			}
			if (ctx->args->msg_handler != NULL) {
				ctx->args->msg_handler(server_msg, ctx->args->userdata);
			}
		}
	}

	buxn_dbg_client_msg_t term_msg = {
		.type = CLIENT_MSG_DISCONNECTED,
	};
	bio_wait_and_send_message(
		!ctx->should_terminate,
		ctx->service_mailbox,
		term_msg
	);
}

static void
client_entry(void* userdata) {
	buxn_dbg_client_args_t args;
	buxn_dbg_client_mailbox_t mailbox;
	bio_get_service_info(userdata, &mailbox, &args);
	bio_set_coro_data(&args, &BUXN_CLIENT_DATA);

	bserial_io_t* io = buxn_dbg_make_bserial_io_from_socket(args.socket);
	client_reader_ctx_t ctx = {
		.args = &args,
		.bserial_in = io->in,
		.service_mailbox = mailbox,
	};
	bio_coro_t reader_coro = bio_spawn(reader_entry, &ctx);

	bio_service_loop(msg, mailbox) {
		switch (msg.type) {
			case CLIENT_MSG_DISCONNECTED:
				goto end;
			case CLIENT_MSG_SEND: {
				if (buxn_dbgx_protocol_msg(io->out, NULL, &msg.msg) != BSERIAL_OK) {
					break;
				}

				if (msg.msg.type == BUXN_DBGX_MSG_CORE) {
					barray_push(ctx.pending_cmds, msg, NULL);
				} else {
					bio_respond(msg) { }
				}
			} break;
		}
	}

end:
	bio_net_close(args.socket, NULL);
	ctx.should_terminate = true;
	bio_join(reader_coro);
	barray_free(NULL, ctx.pending_cmds);

	buxn_dbg_destroy_bserial_io(io);
}

buxn_dbg_client_t
buxn_dbg_start_client(const buxn_dbg_client_args_t* args) {
	buxn_dbg_client_t client;
	bio_start_service(&client, client_entry, *args, 4);
	return client;
}

void
buxn_dbg_stop_client(buxn_dbg_client_t client) {
	buxn_dbg_client_args_t* args = bio_get_coro_data(client.coro, &BUXN_CLIENT_DATA);
	if (args != NULL) {
		bio_net_close(args->socket, NULL);
		bio_stop_service(client);
	}
}

bio_call_status_t
buxn_dbg_client_send(buxn_dbg_client_t client, buxn_dbgx_msg_t msg) {
	buxn_dbg_client_msg_t msg_to_service = {
		.type = CLIENT_MSG_SEND,
		.msg = msg,
	};
	if (
		msg.type == BUXN_DBGX_MSG_CORE
		|| msg.type == BUXN_DBGX_MSG_LOG
	) {
		bio_signal_t cancel_signal = { 0 };
		return bio_call_service(client, msg_to_service, cancel_signal);
	} else {
		bio_notify_service(client, msg_to_service, true);
		return BIO_CALL_OK;
	}
}
