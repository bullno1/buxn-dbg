#ifndef BUXN_DBG_SERVER_H
#define BUXN_DBG_SERVER_H

#include <bio/mailbox.h>
#include "../common.h"

typedef struct {
	buxn_dbg_transport_info_t connect_transport;
	buxn_dbg_transport_info_t listen_transport;
} buxn_dbg_server_args_t;

int
buxn_dbg_server_entry(/* buxn_dbg_server_args_t* */ void* userdata);

#endif
