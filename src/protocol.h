#ifndef BUXN_DBGX_PROTOCOL_H
#define BUXN_DBGX_PROTOCOL_H

#include <buxn/dbg/protocol.h>

typedef enum {
	BUXN_DBGX_MSG_BYE         = 0,
	BUXN_DBGX_MSG_INIT        = 1,
	BUXN_DBGX_MSG_INIT_REP    = 2,
	BUXN_DBGX_MSG_CORE        = 3,
	BUXN_DBGX_MSG_SET_FOCUS   = 4,
	BUXN_DBGX_MSG_INFO_PUSH   = 5,
} buxn_dbgx_msg_type_t;

#define BUXN_DBGX_SUB_NONE        (0)
#define BUXN_DBGX_SUB_INFO_PUSH   (1 << 0)
#define BUXN_DBGX_SUB_FOCUS       (1 << 1)
#define BUXN_DBGX_SUB_VM_STATE    (1 << 2)

#define BUXN_DBGX_INIT_OPT_NONE        (0)
#define BUXN_DBGX_INIT_OPT_INFO        (1 << 0)
#define BUXN_DBGX_INIT_OPT_SUPP_FILES  (1 << 1)

typedef struct {
	uint16_t vector_addr;
	uint16_t pc;
	uint8_t brkp_id;
	bool vm_executing;
	bool vm_paused;
	uint16_t focus;
} buxn_dbgx_info_t;

typedef struct {
	const char* dbg_filename;
	const char* src_dir;
} buxn_dbgx_support_files_t;

typedef struct {
	const char* client_name;
	uint32_t subscriptions;
	uint32_t options;
} buxn_dbgx_init_t;

typedef struct {
	buxn_dbgx_info_t* info;
	buxn_dbgx_support_files_t* support_files;
} buxn_dbgx_init_rep_t;

typedef struct {
	uint16_t address;
} buxn_dbgx_set_focus_t;

typedef struct {
	buxn_dbgx_msg_type_t type;
	union {
		buxn_dbgx_init_t init;
		buxn_dbgx_init_rep_t init_rep;
		buxn_dbg_msg_t core;
		buxn_dbgx_info_t info_push;
		buxn_dbgx_set_focus_t set_focus;
	};
} buxn_dbgx_msg_t;

bserial_status_t
buxn_dbgx_protocol_msg_header(bserial_ctx_t* ctx, buxn_dbgx_msg_t* msg);

bserial_status_t
buxn_dbgx_protocol_msg_body(
	bserial_ctx_t* ctx,
	buxn_dbg_msg_buffer_t buffer,
	buxn_dbgx_msg_t* msg
);

static inline bserial_status_t
buxn_dbgx_protocol_msg(
	bserial_ctx_t* ctx,
	buxn_dbg_msg_buffer_t buffer,
	buxn_dbgx_msg_t* msg
) {
	BSERIAL_CHECK_STATUS(buxn_dbgx_protocol_msg_header(ctx, msg));
	BSERIAL_CHECK_STATUS(buxn_dbgx_protocol_msg_body(ctx, buffer, msg));
	return BSERIAL_OK;
}

#endif
