#include "client.h"
#include <barray.h>
#include <string.h>
#include "common.h"

static const bio_tag_t BUXN_CLIENT_DATA = BIO_TAG_INIT("buxn.client.data");

typedef enum {
	CLIENT_MSG_DISCONNECTED,
	CLIENT_MSG_INIT,
	CLIENT_MSG_STOP,
	CLIENT_MSG_DBG_CMD,
	CLIENT_MSG_SET_FOCUS,
} client_msg_type_t;

struct buxn_dbg_client_msg_s {
	BIO_SERVICE_MSG

	client_msg_type_t type;
	union {
		struct {
			const buxn_dbgx_init_t* msg;
			const buxn_dbgx_init_rep_t* rep;
		} init;
		buxn_dbg_cmd_t dbg_cmd;
		uint16_t focus;
	};
};

typedef BIO_MAILBOX(buxn_dbg_client_msg_t) buxn_dbg_client_mailbox_t;

typedef struct {
	buxn_dbg_client_args_t* args;
	bserial_ctx_t* bserial_in;
	buxn_dbg_client_mailbox_t service_mailbox;
	barray(buxn_dbg_client_msg_t) pending_cmds;
	bool should_terminate;
} client_reader_ctx_t;

static bool
next_pending_cmd(client_reader_ctx_t* ctx, buxn_dbg_client_msg_t* cmd) {
	size_t num_pending_cmds = barray_len(ctx->pending_cmds);
	if (num_pending_cmds == 0) { return false; }

	*cmd = ctx->pending_cmds[0];
	memmove(
		ctx->pending_cmds,
		ctx->pending_cmds + 1,
		sizeof(*cmd) * (num_pending_cmds - 1)
	);
	barray_resize(ctx->pending_cmds, num_pending_cmds - 1, NULL);
	return true;
}

static void
reader_entry(void* userdata) {
	client_reader_ctx_t* ctx = userdata;
	bio_set_coro_name("client/reader");
	buxn_dbg_msg_buffer_t init_buf;

	while (!ctx->should_terminate) {
		buxn_dbgx_msg_t server_msg = { 0 };
		if (buxn_dbgx_protocol_msg_header(ctx->bserial_in, &server_msg) != BSERIAL_OK) {
			break;
		}

		if (server_msg.type == BUXN_DBGX_MSG_CORE) {
			if (buxn_dbg_protocol_msg_header(ctx->bserial_in, &server_msg.core) != BSERIAL_OK) {
				break;
			}

			if (server_msg.core.type == BUXN_DBG_MSG_COMMAND_REP) {
				buxn_dbg_client_msg_t pending_cmd;
				if (!next_pending_cmd(ctx, &pending_cmd)) { break; }
				server_msg.core.cmd = pending_cmd.dbg_cmd;
				if (buxn_dbg_protocol_msg_body(ctx->bserial_in, NULL, &server_msg.core) != BSERIAL_OK) {
					break;
				}

				// TODO: handle cancellation
				bio_respond(pending_cmd) { }
			} else {
				if (buxn_dbg_protocol_msg_body(ctx->bserial_in, NULL, &server_msg.core) != BSERIAL_OK) {
					break;
				}
				if (ctx->args->msg_handler != NULL) {
					ctx->args->msg_handler(server_msg, ctx->args->userdata);
				}
			}
		} else if (
			server_msg.type == BUXN_DBGX_MSG_INIT_REP
		) {
			buxn_dbg_client_msg_t pending_cmd;
			if (!next_pending_cmd(ctx, &pending_cmd)) { break; }
			if (pending_cmd.init.rep != NULL) {
				server_msg.init_rep = *pending_cmd.init.rep;
			}

			if (buxn_dbgx_protocol_msg_body(ctx->bserial_in, init_buf, &server_msg) != BSERIAL_OK) {
				break;
			}

			bio_respond(pending_cmd) { }
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
	bio_set_coro_name("client");

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
			case CLIENT_MSG_INIT: {
				buxn_dbgx_msg_t init = {
					.type = BUXN_DBGX_MSG_INIT,
					.init = *msg.init.msg,
				};
				barray_push(ctx.pending_cmds, msg, NULL);
				if (buxn_dbgx_protocol_msg(io->out, NULL, &init) != BSERIAL_OK) {
					goto end;
				}
			} break;
			case CLIENT_MSG_STOP: {
				buxn_dbgx_msg_t bye = { .type = BUXN_DBGX_MSG_BYE };
				if (buxn_dbgx_protocol_msg(io->out, NULL, &bye) != BSERIAL_OK) {
					goto end;
				}
				bio_respond(msg) { }
			} break;
			case CLIENT_MSG_DBG_CMD: {
				buxn_dbgx_msg_t dbg_cmd = {
					.type = BUXN_DBGX_MSG_CORE,
					.core = {
						.type = BUXN_DBG_MSG_COMMAND_REQ,
						.cmd = msg.dbg_cmd,
					},
				};
				barray_push(ctx.pending_cmds, msg, NULL);
				BIO_TRACE("Send");
				if (buxn_dbgx_protocol_msg(io->out, NULL, &dbg_cmd) != BSERIAL_OK) {
					goto end;
				}
				BIO_TRACE("Sent");
			} break;
			case CLIENT_MSG_SET_FOCUS: {
				buxn_dbgx_msg_t set_focus = {
					.type = BUXN_DBGX_MSG_SET_FOCUS,
					.set_focus.address = msg.focus,
				};
				if (buxn_dbgx_protocol_msg(io->out, NULL, &set_focus) != BSERIAL_OK) {
					goto end;
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
	buxn_dbg_client_msg_t msg_to_service = {
		.type = CLIENT_MSG_STOP,
	};
	bio_signal_t cancel_signal = { 0 };
	bio_call_service(client, msg_to_service, cancel_signal);

	buxn_dbg_client_args_t* args = bio_get_coro_data(client.coro, &BUXN_CLIENT_DATA);
	if (args != NULL) {
		bio_net_close(args->socket, NULL);
		bio_stop_service(client);
	}
}

bool
buxn_dbg_make_client_ex(
	buxn_dbg_client_t* client,
	const struct buxn_dbg_transport_info_s* transport,
	const buxn_dbg_client_args_t* args,
	const buxn_dbgx_init_t* init_info,
	const buxn_dbgx_init_rep_t* init_rep
) {
	bio_error_t error;
	bio_socket_t sock;
	if (!bio_net_connect(
		BIO_SOCKET_STREAM,
		&transport->net.addr,
		transport->net.port,
		&sock,
		&error
	)) {
		BIO_ERROR(
			"Error while connecting: (" BIO_ERROR_FMT ")",
			BIO_ERROR_FMT_ARGS(&error)
		);
		return false;
	}

	buxn_dbg_client_args_t args_with_sock = *args;
	args_with_sock.socket = sock;
	*client = buxn_dbg_start_client(&args_with_sock);

	buxn_dbg_client_msg_t init_msg = {
		.type = CLIENT_MSG_INIT,
		.init = {
			.msg = init_info,
			.rep = init_rep,
		},
	};
	bio_signal_t no_cancel = { 0 };
	bio_call_status_t status = bio_call_service(*client, init_msg, no_cancel);
	if (status == BIO_CALL_OK) {
		return true;
	} else {
		BIO_ERROR("Could not initialize");

		bio_net_close(sock, NULL);
		bio_stop_service(*client);
		return false;
	}
}

bio_call_status_t
buxn_dbg_client_send_dbg_cmd(buxn_dbg_client_t client, buxn_dbg_cmd_t cmd) {
	buxn_dbg_client_msg_t msg = {
		.type = CLIENT_MSG_DBG_CMD,
		.dbg_cmd = cmd,
	};
	bio_signal_t no_cancel = { 0 };
	return bio_call_service(client, msg, no_cancel);
}

void
buxn_dbg_client_set_focus(buxn_dbg_client_t client, uint16_t address) {
	buxn_dbg_client_msg_t msg = {
		.type = CLIENT_MSG_SET_FOCUS,
		.focus = address,
	};
	bio_notify_service(client, msg, true);
}
