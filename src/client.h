#ifndef BUXN_DBG_CLIENT_H
#define BUXN_DBG_CLIENT_H

#include "common.h"
#include <bio/service.h>
#include <bio/net.h>

typedef struct buxn_dbg_client_msg_s buxn_dbg_client_msg_t;
typedef BIO_SERVICE(buxn_dbg_client_msg_t) buxn_dbg_client_t;

typedef struct {
	bio_socket_t socket;
	void* userdata;
	void (*msg_handler)(buxn_dbgx_msg_t msg, void* userdata);
} buxn_dbg_client_args_t;

buxn_dbg_client_t
buxn_dbg_start_client(const buxn_dbg_client_args_t* args);

void
buxn_dbg_stop_client(buxn_dbg_client_t client);

bio_call_status_t
buxn_dbg_client_send(buxn_dbg_client_t client, buxn_dbgx_msg_t msg);

static inline bio_call_status_t
buxn_dbg_client_send_dbg_cmd(buxn_dbg_client_t client, buxn_dbg_cmd_t cmd) {
	return buxn_dbg_client_send(client, (buxn_dbgx_msg_t){
		.type = BUXN_DBGX_MSG_CORE,
		.core = {
			.type = BUXN_DBG_MSG_COMMAND_REQ,
			.cmd = cmd,
		},
	});
}

#endif
