#ifndef BUXN_DBGX_PROTOCOL_H
#define BUXN_DBGX_PROTOCOL_H

#include <buxn/dbg/protocol.h>
#include <bio/bio.h>

typedef enum {
	BUXN_DBGX_MSG_CORE   = 0,
	BUXN_DBGX_MSG_FOCUS  = 1,
	BUXN_DBGX_MSG_LOG    = 2,
} buxn_dbgx_msg_type_t;

typedef enum {
	BUXN_DBGP_FOCUS_HOVER    = 0,
	BUXN_DBGP_FOCUS_CURRENT  = 1,
} buxn_dbgp_focus_type_t;

typedef struct {
	buxn_dbgx_msg_type_t type;
	union {
		buxn_dbg_msg_t core;

		struct {
			buxn_dbgp_focus_type_t type;
			uint16_t address;
		} focus;

		struct {
			bio_log_level_t level;
			int line;
			const char* file;
			const char* msg;
		} log;
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
