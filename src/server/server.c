#ifdef __linux__
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <linux/prctl.h>
#include <sys/prctl.h>
#endif

#include "server.h"
#include "client.h"
#include "vm.h"
#include "../protocol.h"
#include "../logger.h"
#include "../symbol.h"
#include <time.h>
#include <bio/mailbox.h>
#include <string.h>
#include <buxn/dbg/transports/stream.h>

#define MAX_CLIENTS 32

typedef enum {
	SERVER_MSG_VM_NOTIFICATION,
	SERVER_MSG_VM_DISCONNECTED,
	SERVER_MSG_NEW_CLIENT,
	SERVER_MSG_SET_FOCUS,
	SERVER_MSG_BROADCAST,
	SERVER_MSG_TERMINATE_CLIENT,
	SERVER_MSG_CLIENT_TERMINATED,
} server_msg_type_t;

typedef struct {
	server_msg_type_t type;

	union {
		struct {
			int id;
		} terminate_client;

		struct {
			int client_id;
			uint16_t address;
		} set_focus;

		struct {
			buxn_dbg_msg_t msg;
		} vm_notification;

		struct {
			int id;
		} client_terminated;

		struct {
			bio_socket_t socket;
		} new_client;

		struct {
			buxn_dbgx_msg_t msg;
			uint32_t mask;
			int exclude;
		} broadcast;
	};
} server_msg_t;

typedef BIO_MAILBOX(server_msg_t) server_mailbox_t;

struct buxn_dbg_vm_controller_s {
	server_mailbox_t server_mailbox;
	buxn_dbgx_info_t info;
};

typedef struct {
	server_mailbox_t server_mailbox;
	buxn_dbg_vm_handler_t vm;
	buxn_dbgx_config_t config;
	buxn_dbg_vm_controller_t* vm_controller;
} client_shared_ctx_t;

struct buxn_dbg_client_controller_s {
	int id;
	bool initialized;
	uint32_t subscriptions;
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
	bio_set_coro_name("server/acceptor");

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

static void
broadcast_to_clients(
	buxn_dbg_client_controller_t* clients,
	buxn_dbgx_msg_t msg,
	uint32_t mask,
	int exclude_client
) {
	for (int i = 0; i < MAX_CLIENTS; ++i) {
		buxn_dbg_client_controller_t* client = &clients[i];
		if (
			client->id != -1
			&& i != exclude_client
			&& client->initialized
			&& ((client->subscriptions & mask) > 0)
		) {
			if (!buxn_dbg_notify_client_async(clients[i].client, msg)) {
				BIO_WARN("Client %d takes too long to process messages", i);
				buxn_dbg_stop_client_handler(clients[i].client);
			}
		}
	}
}

static bool
buxn_dbg_server_connect(
	buxn_dbg_transport_info_t connect_transport,
	bio_file_t* conn_file,
	bio_socket_t* conn_socket
) {
	bio_error_t error = { 0 };
	switch (connect_transport.type) {
		case BUXN_DBG_TRANSPORT_FILE: {
			BIO_INFO("Opening %s", connect_transport.file);
			bio_file_t file;
			if (!bio_fopen(&file, connect_transport.file, "r+", &error)) {
				BIO_ERROR(
					"Error while opening: %s (" BIO_ERROR_FMT ")",
					connect_transport.file,
					BIO_ERROR_FMT_ARGS(&error)
				);
				return false;
			}
			*conn_file = file;
		} break;
		case BUXN_DBG_TRANSPORT_NET_LISTEN: {
			BIO_INFO("Waiting for connection from VM");
			bio_socket_t server;
			if (!bio_net_listen(
				BIO_SOCKET_STREAM,
				&connect_transport.net.addr,
				connect_transport.net.port,
				&server,
				&error
			)) {
				BIO_ERROR(
					"Error while listening: (" BIO_ERROR_FMT ")",
					BIO_ERROR_FMT_ARGS(&error)
				);
				return false;
			}

			bio_socket_t client;
			if (!bio_net_accept(server, &client, &error)) {
				BIO_ERROR(
					"Error while accepting: (" BIO_ERROR_FMT ")",
					BIO_ERROR_FMT_ARGS(&error)
				);
				bio_net_close(server, NULL);
				return false;
			}
			BIO_INFO("VM connected");

			bio_net_close(server, NULL);
			*conn_socket = client;
		} break;
		case BUXN_DBG_TRANSPORT_NET_CONNECT: {
			BIO_INFO("Connecting to VM");
			bio_socket_t sock;
			if (!bio_net_connect(
				BIO_SOCKET_STREAM,
				&connect_transport.net.addr,
				connect_transport.net.port,
				&sock,
				&error
			)) {
				BIO_ERROR(
					"Error while connecting: " BIO_ERROR_FMT,
					BIO_ERROR_FMT_ARGS(&error)
				);
				return false;
			}
			BIO_INFO("Connected to VM");
			*conn_socket = sock;
		} break;
		default:
			BIO_ERROR("Unknown transport type: %d", connect_transport.type);
			return false;
	}

	return true;
}

static bool
buxn_dbg_server_wrap(
	int argc, const char** argv,
	bio_socket_t* conn_socket
) {
#ifdef __linux__
	// Generate a random transport address for the wrapped process
	char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	char server_sock_name[] = "@buxn/wrap/0123456789";
	char vm_sock_name[] = "buxn/wrap/0123456789";

	srand(time(NULL));
	for (int i = 0; i < 10; ++i) {
		char random_char = charset[rand() % (sizeof(charset) - 1)];
		server_sock_name[i + sizeof("@buxn/wrap/") - 1] = random_char;
		vm_sock_name[i + sizeof("buxn/wrap/") - 1] = random_char;
	}

	BIO_DEBUG("Using %s for connection", server_sock_name);

	pid_t child_proc = fork();
	if (child_proc == 0) {  // Child
		prctl(PR_SET_PDEATHSIG, SIGTERM);
		signal(SIGPIPE, SIG_IGN);
		int fd = buxn_dbg_transport_abstract_connect(vm_sock_name);

		char buf[sizeof("2147483647")];
		snprintf(buf, sizeof(buf), "%d", fd);
		setenv("BUXN_DBG_FD", buf, 1);

		if (execvp(argv[0], (char**)argv) < 0) {
			exit(1);
		}
		return false;  // Unreachable
	} else if (child_proc > 0) {  // Parent
		// Use net logger from this point since we relinquish std streams to the
		// child.
		buxn_dbg_set_logger(buxn_dbg_add_net_logger(BIO_LOG_LEVEL_TRACE, "server"));
		buxn_dbg_transport_info_t info = {
			.type = BUXN_DBG_TRANSPORT_NET_LISTEN,
			.net = {
				.addr = {
					.type = BIO_ADDR_NAMED,
					.named = {
						.len = sizeof(server_sock_name) - 1,
					},
				},
				.port = BIO_PORT_ANY,
			},
		};
		memcpy(&info.net.addr.named.name, server_sock_name, sizeof(server_sock_name) - 1);
		return buxn_dbg_server_connect(info, NULL, conn_socket);
	} else {  // Failure
		BIO_ERROR("Could not fork: %s", strerror(errno));
		return false;
	}
#else
	BIO_ERROR("Not supported");
	return false;
#endif
}

static bool
str_ends_with(const char *str, const char *suffix) {
	size_t lenstr = strlen(str);
	size_t lensuffix = strlen(suffix);
	if (lensuffix >  lenstr) { return false; }
	return strncmp(str + lenstr - lensuffix, suffix, lensuffix) == 0;
}

int
buxn_dbg_server_entry(/* buxn_dbg_server_args_t* */ void* userdata) {
	bio_set_coro_name("server");
	buxn_dbg_server_args_t* args = userdata;

	buxn_dbgx_config_t config = args->config;

	char dbg_filename_buf[1024];
	if (args->argc > 1 && config.dbg_filename == NULL) {
		BIO_DEBUG("Guessing path to .rom.dbg file from command");

		for (int i = 1; i < args->argc; ++i) {
			const char* arg = args->argv[i];
			if (str_ends_with(arg, ".rom")) {
				BIO_DEBUG("Trying %s.dbg", arg);

				int len = snprintf(
					dbg_filename_buf,
					sizeof(dbg_filename_buf),
					"%s.dbg",
					args->argv[i]
				);
				if (len > 0 && len < (int)sizeof(dbg_filename_buf)) {
					bio_file_t file;
					if (bio_fopen(&file, dbg_filename_buf, "r", NULL)) {
						config.dbg_filename = dbg_filename_buf;
						BIO_DEBUG("Picking %s", dbg_filename_buf);
						bio_fclose(file, NULL);
						break;
					}
				}
			}
		}
	}

	// Use absolute path so that clients can open files from any dir
	if (config.dbg_filename != NULL) {
		config.dbg_filename = realpath(config.dbg_filename, NULL);
	}

	char src_dir_buf[1024];
	// Try to guess the source directory from the .rom.dbg file
	if (config.src_dir == NULL && config.dbg_filename != NULL) {
		BIO_DEBUG("Guessing path to source directory from debug info file");

		buxn_dbg_symtab_t* symtab = buxn_dbg_load_symbols(config.dbg_filename);
		if (symtab != NULL) {
			// Pick the first source file
			const char* src_file = NULL;
			for (int i = 0; i < symtab->num_symbols; ++i) {
				if (symtab->symbols[i].region.filename != NULL) {
					src_file = symtab->symbols[i].region.filename;
				}
			}

			// Try to search upward from the path of debug file
			int path_len = (int)strlen(config.dbg_filename);
			for (int i = path_len - 1; i >= 1; --i) {
				char ch = config.dbg_filename[i];
				if (ch == '/' || ch == '\\') {
					int len = snprintf(
						src_dir_buf,
						sizeof(src_dir_buf),
						"%.*s/%s",
						i, config.dbg_filename,
						src_file
					);
					if (len > 0 && len < (int)sizeof(src_dir_buf)) {
						BIO_DEBUG("Trying %s", src_dir_buf);
						bio_file_t file;
						if (bio_fopen(&file, src_dir_buf, "r", NULL)) {
							src_dir_buf[i] = '\0';

							BIO_DEBUG("Picking %s", src_dir_buf);
							config.src_dir = src_dir_buf;
							bio_fclose(file, NULL);
							break;
						}
					}
				}
			}

			buxn_dbg_unload_symbols(symtab);
		} else {
			BIO_WARN("Could not open debug info file");
		}
	}

	if (config.src_dir != NULL) {
		config.src_dir = realpath(config.src_dir, NULL);
	} else {
		config.src_dir = realpath("./", NULL);
	}

	// Connect to VM
	bio_error_t error = { 0 };
	bio_file_t vm_conn_file = { 0 };
	bio_socket_t vm_conn_socket = { 0 };
	bool should_run;
	if (args->argc == 0) {  // Connect mode
		should_run = buxn_dbg_server_connect(
			args->connect_transport,
			&vm_conn_file,
			&vm_conn_socket
		);
	} else {  // Wrapper mode
		should_run = buxn_dbg_server_wrap(
			args->argc, args->argv,
			&vm_conn_socket
		);
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

	server_mailbox_t mailbox;
	bio_open_mailbox(&mailbox, 32);

	client_shared_ctx_t client_shared_ctx = {
		.server_mailbox = mailbox,
		.config = config,
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
	if (should_run && !bio_net_listen(
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
		.info = {
			.brkp_id = BUXN_DBG_BRKP_NONE,
			.focus = 0x0100,
		},
	};
	if (should_run) {
		client_shared_ctx.vm = buxn_dbg_start_vm_handler(&(buxn_dbg_vm_handler_args_t){
			.dbg_in = vm_bserial_in,
			.dbg_out = vm_bserial_out,
			.controller = &vm_controller,
			.vm_conn_file = vm_conn_file,
			.vm_conn_socket = vm_conn_socket,
		});
		client_shared_ctx.vm_controller = &vm_controller;
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
				if (vm_msg.type == BUXN_DBG_MSG_PAUSED) {
					// Cache pc so new clients immediately get up-to-date pc
					buxn_dbg_cmd_t get_pc = {
						.type = BUXN_DBG_CMD_INFO,
						.info = {
							.type = BUXN_DBG_INFO_PC,
							.pc = &vm_controller.info.pc,
						},
					};
					bio_signal_t no_cancel = { 0 };
					buxn_dbg_send_vm_cmd(client_shared_ctx.vm, get_pc, no_cancel);

					// Focus on new pc
					vm_controller.info.focus = vm_controller.info.pc;

					// Push new VM and focus tate
					buxn_dbgx_msg_t info_push = {
						.type = BUXN_DBGX_MSG_INFO_PUSH,
						.info_push = vm_controller.info,
					};
					broadcast_to_clients(
						clients,
						info_push,
						BUXN_DBGX_SUB_INFO_PUSH,
						-1
					);
				} else if (vm_msg.type == BUXN_DBG_MSG_END_BREAK) {
					buxn_dbgx_msg_t info_push = {
						.type = BUXN_DBGX_MSG_INFO_PUSH,
						.info_push = vm_controller.info,
					};
					broadcast_to_clients(
						clients,
						info_push,
						BUXN_DBGX_SUB_INFO_PUSH,
						-1
					);
				}

				buxn_dbgx_msg_t notification = {
					.type = BUXN_DBGX_MSG_CORE,
					.core = vm_msg,
				};
				broadcast_to_clients(
					clients,
					notification,
					BUXN_DBGX_SUB_VM_STATE,
					-1
				);
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
						.id = controller->id,
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
			case SERVER_MSG_SET_FOCUS: {
				vm_controller.info.focus = msg.set_focus.address;
				buxn_dbgx_msg_t notification = {
					.type = BUXN_DBGX_MSG_SET_FOCUS,
					.set_focus = { .address = msg.set_focus.address },
				};
				broadcast_to_clients(
					clients,
					notification,
					BUXN_DBGX_SUB_FOCUS,
					msg.set_focus.client_id
				);
			} break;
			case SERVER_MSG_BROADCAST: {
				broadcast_to_clients(
					clients,
					msg.broadcast.msg,
					msg.broadcast.mask,
					msg.broadcast.exclude
				);
			} break;
			case SERVER_MSG_CLIENT_TERMINATED: {
				BIO_INFO("Client %d disconnected", msg.client_terminated.id);
				clients[msg.client_terminated.id].id = -1;
				clients[msg.client_terminated.id].initialized = false;
				clients[msg.client_terminated.id].client = (buxn_dbg_client_handler_t){ 0 };
			} break;
			case SERVER_MSG_TERMINATE_CLIENT: {
				buxn_dbg_stop_client_handler(clients[msg.terminate_client.id].client);
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

#ifdef __linux__
	free((char*)config.dbg_filename);
	free((char*)config.src_dir);
#endif

	return 0;
}

void
buxn_dbg_vm_notify(buxn_dbg_vm_controller_t* controller, buxn_dbg_msg_t msg) {
	switch (msg.type) {
		case BUXN_DBG_MSG_BEGIN_EXEC:
			controller->info.vm_executing = true;
			controller->info.vector_addr = msg.addr;
			controller->info.pc = msg.addr;
			break;
		case BUXN_DBG_MSG_END_EXEC:
			controller->info.vm_executing = false;
			break;
		case BUXN_DBG_MSG_BEGIN_BREAK:
			controller->info.brkp_id = msg.brkp_id;
			break;
		case BUXN_DBG_MSG_END_BREAK:
			controller->info.vm_paused = false;
			controller->info.brkp_id = BUXN_DBG_BRKP_NONE;
			break;
		case BUXN_DBG_MSG_PAUSED:
			controller->info.vm_paused = true;
			break;
		case BUXN_DBG_MSG_COMMAND_REQ:
		case BUXN_DBG_MSG_COMMAND_REP:
			break;
	}

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

static void
terminate_client(buxn_dbg_client_controller_t* controller) {
	server_msg_t msg_to_server = {
		.type = SERVER_MSG_TERMINATE_CLIENT,
		.terminate_client.id = controller->id,
	};
	bio_wait_and_send_message(true, controller->shared_ctx->server_mailbox, msg_to_server);
}

void
buxn_dbg_client_request(buxn_dbg_client_controller_t* controller, buxn_dbgx_msg_t msg) {
	if (!controller->initialized && msg.type != BUXN_DBGX_MSG_INIT) {
		BIO_WARN("Client %d sends message without initialization", controller->id);
		terminate_client(controller);
		return;
	}

	switch (msg.type) {
		case BUXN_DBGX_MSG_INIT: {
			BIO_DEBUG("Initializing");
			if (controller->initialized) {
				BIO_WARN("Client %d sent init twice", controller->id);
				terminate_client(controller);
				return;
			}

			buxn_dbgx_msg_t rep = { .type = BUXN_DBGX_MSG_INIT_REP };

			if (msg.init.options & BUXN_DBGX_INIT_OPT_INFO) {
				rep.init_rep.info = &controller->shared_ctx->vm_controller->info;
			}

			if (msg.init.options & BUXN_DBGX_INIT_OPT_CONFIG) {
				rep.init_rep.config = &controller->shared_ctx->config;
			}

			controller->subscriptions = msg.init.subscriptions;
			buxn_dbg_notify_client_sync(controller->client, rep);

			controller->initialized = true;
			BIO_DEBUG("Initialized");
		} break;
		case BUXN_DBGX_MSG_CORE: {
			if (msg.core.type == BUXN_DBG_MSG_COMMAND_REQ) {
				buxn_dbg_send_vm_cmd(controller->shared_ctx->vm, msg.core.cmd, (bio_signal_t){ 0 });
				msg.core.type = BUXN_DBG_MSG_COMMAND_REP;
				buxn_dbg_notify_client_sync(controller->client, msg);

				if (msg.core.cmd.type == BUXN_DBG_CMD_BRKP_SET) {
					buxn_dbgx_msg_t broadcast_msg = {
						.type = BUXN_DBGX_MSG_BRKP_PUSH,
						.brkp_push = {
							.id = msg.core.cmd.brkp_set.id,
							.brkp = msg.core.cmd.brkp_set.brkp,
						},
					};
					server_msg_t msg_to_server = {
						.type = SERVER_MSG_BROADCAST,
						.broadcast = {
							.mask = BUXN_DBGX_SUB_BRKP,
							.exclude = controller->id,
							.msg = broadcast_msg,
						},
					};
					bio_wait_and_send_message(
						true,
						controller->shared_ctx->server_mailbox,
						msg_to_server
					);
				}
			} else {
				BIO_WARN("Client %d sends invalid core message", controller->id);
				terminate_client(controller);
			}
		} break;
		case BUXN_DBGX_MSG_SET_FOCUS: {
			server_msg_t msg_to_server = {
				.type = SERVER_MSG_SET_FOCUS,
				.set_focus = {
					.client_id = controller->id,
					.address = msg.set_focus.address,
				},
			};
			bio_wait_and_send_message(
				true,
				controller->shared_ctx->server_mailbox,
				msg_to_server
			);
		} break;
		default: {
			BIO_WARN("Client %d sends invalid message", controller->id);
			terminate_client(controller);
		} break;
	}
}

void
buxn_dbg_client_terminated(buxn_dbg_client_controller_t* controller) {
	server_msg_t msg_to_server = {
		.type = SERVER_MSG_CLIENT_TERMINATED,
		.client_terminated.id = controller->id,
	};
	bio_wait_and_send_message(true, controller->shared_ctx->server_mailbox, msg_to_server);
}
