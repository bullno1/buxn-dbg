#ifndef BUXN_DBG_SERVER_CLIENT_HANDLER_H
#define BUXN_DBG_SERVER_CLIENT_HANDLER_H

#include <bio/service.h>
#include <bio/net.h>
#include "../protocol.h"

typedef struct buxn_dbg_client_handler_msg_s buxn_dbg_client_handler_msg_t;
typedef BIO_SERVICE(buxn_dbg_client_handler_msg_t) buxn_dbg_client_handler_t;
typedef struct buxn_dbg_client_controller_s buxn_dbg_client_controller_t;

typedef struct {
	int id;
	bio_socket_t socket;
	buxn_dbg_client_controller_t* controller;
} buxn_dbg_client_args_t;

buxn_dbg_client_handler_t
buxn_dbg_start_client_handler(const buxn_dbg_client_args_t* args);

void
buxn_dbg_stop_client_handler(buxn_dbg_client_handler_t client);

bool
buxn_dbg_notify_client_async(buxn_dbg_client_handler_t client, buxn_dbgx_msg_t msg);

void
buxn_dbg_notify_client_sync(buxn_dbg_client_handler_t client, buxn_dbgx_msg_t msg);

// Provided by controller

extern void
buxn_dbg_client_request(buxn_dbg_client_controller_t* controller, buxn_dbgx_msg_t msg);

extern void
buxn_dbg_client_terminated(buxn_dbg_client_controller_t* controller);

#endif
