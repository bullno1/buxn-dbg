#include "vm.h"

static const bio_tag_t BUXN_VM_DATA = BIO_TAG_INIT("buxn.vm.data");

struct buxn_dbg_vm_handler_msg_s {
	BIO_SERVICE_MSG

	buxn_dbg_cmd_t cmd;
};

typedef BIO_MAILBOX(buxn_dbg_cmd_t) cmd_mailbox_t;
typedef BIO_MAILBOX(buxn_dbg_vm_handler_msg_t) service_mailbox_t;

typedef struct {
	cmd_mailbox_t cmd_mailbox;
	service_mailbox_t service_mailbox;
	bio_file_t vm_conn_file;
	bio_socket_t vm_conn_socket;
} wait_points_t;

typedef struct {
	bserial_ctx_t* dbg_in;
	buxn_dbg_vm_controller_t* controller;
	const wait_points_t* wait_points;
	buxn_dbg_cmd_t pending_cmd;
	bool should_terminate;
} reader_ctx_t;

static void
terminate_wait_points(const wait_points_t* wait_points) {
	// The problem with this service this that the service loop alternates between
	// several wait points:
	//
	// * Writing to socket
	// * Waiting for a command response
	// * Waiting for a new request
	//
	// There is not a single point to signal termination.
	// They are all put into this single struct and function to make termination
	// easier.
	bio_fclose(wait_points->vm_conn_file, NULL);
	bio_net_close(wait_points->vm_conn_socket, NULL);
	bio_close_mailbox(wait_points->cmd_mailbox);
	bio_close_mailbox(wait_points->service_mailbox);
}

static void
reader_entry(void* userdata) {
	BIO_DEBUG("VM reader started");
	reader_ctx_t* ctx = userdata;

	while (!ctx->should_terminate) {
		buxn_dbg_msg_t vm_msg;
		if (buxn_dbg_protocol_msg_header(ctx->dbg_in, &vm_msg) != BSERIAL_OK) {
			if (!ctx->should_terminate) {
				BIO_ERROR("Error while reading message header");
			}
			break;
		}

		if (vm_msg.type == BUXN_DBG_MSG_COMMAND_REP) {
			vm_msg.cmd = ctx->pending_cmd;
			if (buxn_dbg_protocol_msg_body(ctx->dbg_in, NULL, &vm_msg) != BSERIAL_OK) {
				if (!ctx->should_terminate) {
					BIO_ERROR("Error while reading message body");
				}
				break;
			}
			bio_wait_and_send_message(
				!ctx->should_terminate,
				ctx->wait_points->cmd_mailbox,
				ctx->pending_cmd
			);
		} else {
			if (buxn_dbg_protocol_msg_body(ctx->dbg_in, NULL, &vm_msg) != BSERIAL_OK) {
				if (!ctx->should_terminate) {
					BIO_ERROR("Error while reading message body");
				}
				break;
			}
			buxn_dbg_vm_notify(ctx->controller, vm_msg);
		}
	}

	terminate_wait_points(ctx->wait_points);
	BIO_DEBUG("VM reader terminated");
}

static void
service_entry(void* userdata) {
	BIO_DEBUG("VM service started");
	buxn_dbg_vm_handler_args_t args;
	service_mailbox_t service_mailbox;
	bio_get_service_info(userdata, &service_mailbox, &args);

	cmd_mailbox_t cmd_mailbox;
	bio_open_mailbox(&cmd_mailbox, 1);

	wait_points_t wait_points = {
		.cmd_mailbox = cmd_mailbox,
		.service_mailbox = service_mailbox,
		.vm_conn_file = args.vm_conn_file,
		.vm_conn_socket = args.vm_conn_socket,
	};
	bio_set_coro_data(&wait_points, &BUXN_VM_DATA);

	reader_ctx_t reader_ctx = {
		.dbg_in = args.dbg_in,
		.controller = args.controller,
		.wait_points = &wait_points,
	};
	bio_coro_t reader_coro = bio_spawn(reader_entry, &reader_ctx);

	bio_service_loop(msg, service_mailbox) {
		// TODO: This writes the result into the client's buffer without
		// checking for cancellation

		buxn_dbg_cmd_t cmd = msg.cmd;
		reader_ctx.pending_cmd = cmd;
		buxn_dbg_msg_t msg_to_vm = {
			.type = BUXN_DBG_MSG_COMMAND_REQ,
			.cmd = cmd,
		};
		if (buxn_dbg_protocol_msg(args.dbg_out, NULL, &msg_to_vm) != BSERIAL_OK) {
			if (bio_is_mailbox_open(service_mailbox)) {
				BIO_ERROR("Error while sending message to VM");
			}
			break;
		}

		if (!bio_recv_message(cmd_mailbox, &cmd)) {
			BIO_ERROR("Could not retrieve command response");
			break;
		}

		bio_respond(msg) { }
	}

	terminate_wait_points(&wait_points);
	reader_ctx.should_terminate = true;
	bio_join(reader_coro);

	buxn_dbg_vm_disconnected(args.controller);
	BIO_DEBUG("VM service terminated");
}

buxn_dbg_vm_handler_t
buxn_dbg_start_vm_handler(const buxn_dbg_vm_handler_args_t* args) {
	buxn_dbg_vm_handler_t handler;
	bio_start_service(&handler, service_entry, *args, 4);
	return handler;
}

void
buxn_dbg_stop_vm_handler(buxn_dbg_vm_handler_t vm) {
	wait_points_t* wait_points = bio_get_coro_data(vm.coro, &BUXN_VM_DATA);
	if (wait_points != NULL) {
		terminate_wait_points(wait_points);
		bio_stop_service(vm);
	}
}

bio_call_status_t
buxn_dbg_send_vm_cmd(buxn_dbg_vm_handler_t vm, buxn_dbg_cmd_t cmd, bio_signal_t cancel_signal) {
	buxn_dbg_vm_handler_msg_t msg = {
		.cmd = cmd,
	};
	return bio_call_service(vm, msg, cancel_signal);
}
