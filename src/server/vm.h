#ifndef BUXN_DBG_SERVER_VM_HANDLER_H
#define BUXN_DBG_SERVER_VM_HANDLER_H

#include <bio/service.h>
#include <buxn/dbg/protocol.h>
#include "../common.h"

typedef struct buxn_dbg_vm_handler_msg_s buxn_dbg_vm_handler_msg_t;
typedef BIO_SERVICE(buxn_dbg_vm_handler_msg_t) buxn_dbg_vm_handler_t;
typedef struct buxn_dbg_vm_controller_s buxn_dbg_vm_controller_t;

typedef enum {
	BUXN_DBG_CMD_EXECUTED,
	BUXN_DBG_CMD_VM_BUSY,
	BUXN_DBG_CMD_VM_DISCONNECTED,
} buxn_dbg_cmd_status_t;

typedef struct {
	bserial_ctx_t* dbg_in;
	bserial_ctx_t* dbg_out;
	bio_file_t vm_conn_file;
	bio_socket_t vm_conn_socket;
	buxn_dbg_vm_controller_t* controller;
} buxn_dbg_vm_handler_args_t;

buxn_dbg_vm_handler_t
buxn_dbg_start_vm_handler(const buxn_dbg_vm_handler_args_t* args);

void
buxn_dbg_stop_vm_handler(buxn_dbg_vm_handler_t vm);

bio_call_status_t
buxn_dbg_send_vm_cmd(buxn_dbg_vm_handler_t vm, buxn_dbg_cmd_t cmd, bio_signal_t cancel_signal);

// Provided by controller

extern void
buxn_dbg_vm_notify(buxn_dbg_vm_controller_t* controller, buxn_dbg_msg_t msg);

extern void
buxn_dbg_vm_disconnected(buxn_dbg_vm_controller_t* controller);

#endif
