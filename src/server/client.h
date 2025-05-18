#ifndef BUXN_DBG_SERVER_CLIENT_HANDLER_H
#define BUXN_DBG_SERVER_CLIENT_HANDLER_H

#include "../common.h"
#include <bio/service.h>

typedef struct buxn_dbg_client_handler_msg_s buxn_dbg_client_handler_msg_t;
typedef BIO_SERVICE(buxn_dbg_client_handler_msg_t) buxn_dbg_client_handler_t;
typedef struct buxn_dbg_client_controller_s buxn_dbg_client_controller_t;

typedef struct {
	bserial_socket_io_t io;
	buxn_dbg_client_controller_t* controller;
} buxn_dbg_client_args_t;

buxn_dbg_client_handler_t
buxn_dbg_start_client_handler(const buxn_dbg_client_args_t* args);

void
buxn_dbg_stop_client_handler(buxn_dbg_client_handler_t client);

bool
buxn_dbg_notify_client(buxn_dbg_client_handler_t client, buxn_dbgx_msg_t msg);

// Provided by controller

extern void
buxn_dbg_client_request(buxn_dbg_client_controller_t* controller, buxn_dbgx_msg_t msg);

extern void
buxn_dbg_client_terminated(buxn_dbg_client_controller_t* controller);

#endif
