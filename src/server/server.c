#include "server.h"
#include "client.h"
#include "vm.h"
#include <bio/mailbox.h>

#define MAX_CLIENTS 32

typedef enum {
	SERVER_MSG_VM_NOTIFICATION,
	SERVER_MSG_VM_DISCONNECTED,
	SERVER_MSG_NEW_CLIENT,
	SERVER_MSG_CLIENT_TERMINATED,
	SERVER_MSG_CLIENT_REQUEST,
} server_msg_type_t;

typedef struct {
	server_msg_type_t type;

	union {
		struct {
			buxn_dbg_msg_t msg;
		} vm_notification;

		struct {
			int id;
			buxn_dbgx_msg_t msg;
		} client_request;

		struct {
			int id;
		} client_terminated;

		struct {
			bio_socket_t socket;
		} new_client;
	};
} server_msg_t;

typedef BIO_MAILBOX(server_msg_t) server_mailbox_t;

struct buxn_dbg_vm_controller_s {
	server_mailbox_t server_mailbox;
};

typedef struct {
	buxn_dbg_vm_handler_t vm;
	server_mailbox_t server_mailbox;
} client_shared_ctx_t;

struct buxn_dbg_client_controller_s {
	int id;
	buxn_dbg_client_handler_t client;
	client_shared_ctx_t* shared_ctx;
};

typedef struct {
	bio_socket_t socket;
	server_mailbox_t server_mailbox;
	bool should_terminate;
} acceptor_ctx_t;

static void
acceptor(void* userdata) {
	acceptor_ctx_t* ctx = userdata;

	bio_error_t error;
	while (!ctx->should_terminate) {
		bio_socket_t client;
		if (bio_net_accept(ctx->socket, &client, &error)) {
			server_msg_t msg = {
				.type = SERVER_MSG_NEW_CLIENT,
				.new_client.socket = client,
			};
			bio_wait_and_send_message(!ctx->should_terminate, ctx->server_mailbox, msg);
		}
	}

	if (!ctx->should_terminate) {
		BIO_ERROR("Error in acceptor: " BIO_ERROR_FMT, BIO_ERROR_FMT_ARGS(&error));
	}
}

int
buxn_dbg_server_entry(/* buxn_dbg_server_args_t* */ void* userdata) {
	buxn_dbg_server_args_t* args = userdata;

	// Connect to VM
	bio_error_t error = { 0 };
	bio_file_t vm_conn_file = { 0 };
	bio_socket_t vm_conn_socket = { 0 };
	switch (args->connect_transport.type) {
		case BUXN_DBG_TRANSPORT_FILE: {
			BIO_INFO("Opening %s", args->connect_transport.file);
			bio_file_t file;
			if (!bio_fopen(&file, args->connect_transport.file, "r+", &error)) {
				BIO_ERROR(
					"Error while opening: %s (" BIO_ERROR_FMT ")",
					args->connect_transport.file,
					BIO_ERROR_FMT_ARGS(&error)
				);
				return 1;
			}
			vm_conn_file = file;
		} break;
		case BUXN_DBG_TRANSPORT_NET_LISTEN: {
			BIO_INFO("Waiting for connection from VM");
			bio_socket_t server;
			if (!bio_net_listen(
				BIO_SOCKET_STREAM,
				&args->connect_transport.net.addr,
				args->connect_transport.net.port,
				&server,
				&error
			)) {
				BIO_ERROR(
					"Error while listening: (" BIO_ERROR_FMT ")",
					BIO_ERROR_FMT_ARGS(&error)
				);
				return 1;
			}

			bio_socket_t client;
			if (!bio_net_accept(server, &client, &error)) {
				BIO_ERROR(
					"Error while accepting: (" BIO_ERROR_FMT ")",
					BIO_ERROR_FMT_ARGS(&error)
				);
				bio_net_close(server, NULL);
				return 1;
			}
			BIO_INFO("VM connected");

			bio_net_close(server, NULL);
			vm_conn_socket = client;
		} break;
		case BUXN_DBG_TRANSPORT_NET_CONNECT: {
			BIO_INFO("Connecting to VM");
			bio_socket_t sock;
			if (!bio_net_connect(
				BIO_SOCKET_STREAM,
				&args->connect_transport.net.addr,
				args->connect_transport.net.port,
				&sock,
				&error
			)) {
				BIO_ERROR(
					"Error while connecting: (" BIO_ERROR_FMT ")",
					BIO_ERROR_FMT_ARGS(&error)
				);
				return 1;
			}
			BIO_INFO("Connected to VM");
			vm_conn_socket = sock;
		} break;
		default:
			BIO_ERROR("Unknown transport type: %d", args->connect_transport.type);
			return 1;
	}

	// Create bserial context for VM
	bserial_ctx_config_t bserial_cfg = buxn_dbg_protocol_recommended_bserial_config();
	size_t bserial_mem_size = bserial_ctx_mem_size(bserial_cfg);
	void* bserial_mem_in = buxn_dbg_malloc(bserial_mem_size);
	void* bserial_mem_out = buxn_dbg_malloc(bserial_mem_size);

	bserial_ctx_t* vm_bserial_in = NULL;
	bserial_ctx_t* vm_bserial_out = NULL;
	bserial_file_io_t file_io = { 0 };
	bserial_socket_io_t socket_io = { 0 };

	if (args->connect_transport.type == BUXN_DBG_TRANSPORT_FILE) {
		bserial_file_io_init(&file_io, vm_conn_file);
		vm_bserial_in = bserial_make_ctx(bserial_mem_in, bserial_cfg, &file_io.in, NULL);
		vm_bserial_out = bserial_make_ctx(bserial_mem_out, bserial_cfg, NULL, &file_io.out);
	} else {
		bserial_socket_io_init(&socket_io, vm_conn_socket);
		vm_bserial_in = bserial_make_ctx(bserial_mem_in, bserial_cfg, &socket_io.in, NULL);
		vm_bserial_out = bserial_make_ctx(bserial_mem_out, bserial_cfg, NULL, &socket_io.out);
	}

	// Server states
	bool should_run = true;

	server_mailbox_t mailbox;
	bio_open_mailbox(&mailbox, 32);

	client_shared_ctx_t client_shared_ctx = {
		.server_mailbox = mailbox,
	};
	buxn_dbg_client_controller_t* clients = buxn_dbg_malloc(sizeof(buxn_dbg_client_controller_t) * MAX_CLIENTS);
	for (int i = 0; i < MAX_CLIENTS; ++i) {
		clients[i] = (buxn_dbg_client_controller_t){
			.id = -1,
			.shared_ctx = &client_shared_ctx,
		};
	}

	// Spawn acceptor coro
	bio_socket_t server_socket = { 0 };
	if (!bio_net_listen(
		BIO_SOCKET_STREAM,
		&args->listen_transport.net.addr,
		args->listen_transport.net.port,
		&server_socket,
		&error
	)) {
		BIO_ERROR(
			"Could not create server socket: (" BIO_ERROR_FMT ")",
			BIO_ERROR_FMT_ARGS(&error)
		);
		should_run = false;
	}

	acceptor_ctx_t acceptor_ctx = {
		.socket = server_socket,
		.server_mailbox = mailbox,
	};
	bio_coro_t acceptor_coro = { 0 };
	if (should_run) {
		acceptor_coro = bio_spawn(acceptor, &acceptor_ctx);
	}

	// Start VM Handler
	buxn_dbg_vm_handler_t vm = { 0 };
	buxn_dbg_vm_controller_t vm_controller = {
		.server_mailbox = mailbox,
	};
	if (should_run) {
		client_shared_ctx.vm = buxn_dbg_start_vm_handler(&(buxn_dbg_vm_handler_args_t){
			.dbg_in = vm_bserial_in,
			.dbg_out = vm_bserial_out,
			.controller = &vm_controller,
			.vm_conn_file = vm_conn_file,
			.vm_conn_socket = vm_conn_socket,
		});
	}

	while (should_run) {
		server_msg_t msg;
		if (!bio_recv_message(mailbox, &msg)) {
			BIO_ERROR("Could not receive message");
			break;
		}

		switch (msg.type) {
			case SERVER_MSG_VM_NOTIFICATION: {
				buxn_dbg_msg_t vm_msg = msg.vm_notification.msg;
				buxn_dbgx_msg_t notification = {
					.type = BUXN_DBGX_MSG_CORE,
					.core = vm_msg,
				};
				for (int i = 0; i < MAX_CLIENTS; ++i) {
					if (clients[i].id != -1) {
						if (!buxn_dbg_notify_client_async(clients[i].client, notification)) {
							BIO_WARN(
								"Client %d takes too long to process messages",
								i
							);
							buxn_dbg_stop_client_handler(clients[i].client);
						}
					}
				}
			} break;
			case SERVER_MSG_VM_DISCONNECTED:
				BIO_WARN("VM disconnected, terminating");
				should_run = false;
				break;
			case SERVER_MSG_NEW_CLIENT: {
				buxn_dbg_client_controller_t* controller = NULL;
				for (int i = 0; i < MAX_CLIENTS; ++i) {
					if (clients[i].id == -1) {
						controller = &clients[i];
						controller->id = i;
						break;
					}
				}

				if (controller != NULL) {
					buxn_dbg_client_args_t client_args = {
						.controller = controller,
						.socket = msg.new_client.socket,
					};
					controller->client = buxn_dbg_start_client_handler(&client_args);
					BIO_INFO("Client %d connected", controller->id);
				} else {
					BIO_WARN("Maximum number of clients reached, rejecting connection");
					bio_net_close(msg.new_client.socket, NULL);
				}
			} break;
			case SERVER_MSG_CLIENT_TERMINATED: {
				BIO_INFO("Client %d disconnected", msg.client_terminated.id);
				clients[msg.client_terminated.id].id = -1;
				clients[msg.client_terminated.id].client = (buxn_dbg_client_handler_t){ 0 };
			} break;
			case SERVER_MSG_CLIENT_REQUEST: {
				buxn_dbgx_msg_t client_req = msg.client_request.msg;
				switch (client_req.type) {
					case BUXN_DBGX_MSG_CORE:
						BIO_WARN("Core message reached main loop");
						break;
					case BUXN_DBGX_MSG_FOCUS:
						break;
					case BUXN_DBGX_MSG_LOG:
						BIO_WARN("Log message reached main loop");
						break;
				}
			} break;
		}
	}
	bio_close_mailbox(mailbox);

	// Stop VM handler
	buxn_dbg_stop_vm_handler(vm);

	// Stop acceptor
	acceptor_ctx.should_terminate = true;
	bio_net_close(acceptor_ctx.socket, NULL);
	bio_join(acceptor_coro);

	// Stop all clients
	for (int i = 0; i < MAX_CLIENTS; ++i) {
		buxn_dbg_stop_client_handler(clients[i].client);
	}

	// Release resources
	buxn_dbg_free(clients);
	buxn_dbg_free(bserial_mem_out);
	buxn_dbg_free(bserial_mem_in);

	return 0;
}

void
buxn_dbg_vm_notify(buxn_dbg_vm_controller_t* controller, buxn_dbg_msg_t msg) {
	server_msg_t msg_to_server = {
		.type = SERVER_MSG_VM_NOTIFICATION,
		.vm_notification.msg = msg,
	};
	bio_wait_and_send_message(true, controller->server_mailbox, msg_to_server);
}

void
buxn_dbg_vm_disconnected(buxn_dbg_vm_controller_t* controller) {
	server_msg_t msg_to_server = {
		.type = SERVER_MSG_VM_DISCONNECTED,
	};
	bio_wait_and_send_message(true, controller->server_mailbox, msg_to_server);
}

void
buxn_dbg_client_request(buxn_dbg_client_controller_t* controller, buxn_dbgx_msg_t msg) {
	if (msg.type == BUXN_DBGX_MSG_CORE) {
		if (msg.core.type == BUXN_DBG_MSG_COMMAND_REQ) {
			buxn_dbg_send_vm_cmd(controller->shared_ctx->vm, msg.core.cmd, (bio_signal_t){ 0 });
			msg.core.type = BUXN_DBG_MSG_COMMAND_REP;
			buxn_dbg_notify_client_sync(controller->client, msg);
		} else {
			BIO_WARN("Client %d sends invalid core message", controller->id);
			buxn_dbg_stop_client_handler(controller->client);
		}
	} else if (msg.type == BUXN_DBGX_MSG_LOG) {
		bio_log(
			msg.log.level, msg.log.file, msg.log.line,
			"Client %d: %s", controller->id, msg.log.msg
		);
	} else {
		server_msg_t msg_to_server = {
			.type = SERVER_MSG_CLIENT_REQUEST,
		};
		bio_wait_and_send_message(true, controller->shared_ctx->server_mailbox, msg_to_server);
	}
}

void
buxn_dbg_client_terminated(buxn_dbg_client_controller_t* controller) {
	server_msg_t msg_to_server = {
		.type = SERVER_MSG_CLIENT_TERMINATED,
	};
	bio_wait_and_send_message(true, controller->shared_ctx->server_mailbox, msg_to_server);
}
