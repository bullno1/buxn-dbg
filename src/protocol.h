#ifndef BUXN_DBGX_PROTOCOL_H
#define BUXN_DBGX_PROTOCOL_H

#include <buxn/dbg/protocol.h>
#include <bio/bio.h>

typedef enum {
	BUXN_DBGX_MSG_BYE         = 0,
	BUXN_DBGX_MSG_INIT        = 1,
	BUXN_DBGX_MSG_CORE        = 2,
	BUXN_DBGX_MSG_LOG         = 3,
	BUXN_DBGX_MSG_INFO_REQ    = 4,
	BUXN_DBGX_MSG_INFO_REP    = 5,
	BUXN_DBGX_MSG_SET_FOCUS   = 6,
} buxn_dbgx_msg_type_t;

typedef struct {
	uint16_t vector_addr;
	uint8_t brkp_id;
	bool vm_executing;
	bool vm_paused;
	uint16_t focus;
} buxn_dbgx_info_t;

typedef struct {
	const char* client_name;
} buxn_dbgx_init_t;

typedef struct {
	buxn_dbgx_msg_type_t type;
	union {
		buxn_dbgx_init_t init;
		buxn_dbg_msg_t core;
		buxn_dbgx_info_t* info;

		struct {
			bio_log_level_t level;
			const char* coro_name;
			int line;
			const char* file;
			const char* msg;
		} log;

		struct {
			uint16_t address;
		} set_focus;
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
