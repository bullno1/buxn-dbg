#ifndef BUXN_DBG_CLIENT_H
#define BUXN_DBG_CLIENT_H

#include <bio/service.h>
#include <bio/net.h>
#include "protocol.h"

typedef struct buxn_dbg_client_msg_s buxn_dbg_client_msg_t;
typedef BIO_SERVICE(buxn_dbg_client_msg_t) buxn_dbg_client_t;
struct buxn_dbg_transport_info_s;

typedef struct {
	bio_socket_t socket;
	void* userdata;
	void (*msg_handler)(buxn_dbgx_msg_t msg, void* userdata);
} buxn_dbg_client_args_t;

buxn_dbg_client_t
buxn_dbg_start_client(const buxn_dbg_client_args_t* args);

void
buxn_dbg_stop_client(buxn_dbg_client_t client);

bool
buxn_dbg_make_client_ex(
	buxn_dbg_client_t* client,
	const struct buxn_dbg_transport_info_s* transport,
	const buxn_dbg_client_args_t* args,
	const buxn_dbgx_init_t* init_info,
	const buxn_dbgx_init_rep_t* init_rep
);

bio_call_status_t
buxn_dbg_client_send_dbg_cmd(buxn_dbg_client_t client, buxn_dbg_cmd_t cmd);

void
buxn_dbg_client_set_focus(buxn_dbg_client_t client, uint16_t address);

#endif
