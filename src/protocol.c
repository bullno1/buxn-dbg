#include "protocol.h"
#include <string.h>

static inline void*
buxn_dbgx_protocol_alloc(buxn_dbg_msg_buffer_t buffer, size_t alignment) {
	return (void*)(((intptr_t)buffer + (intptr_t)alignment - 1) & -(intptr_t)alignment);
}

static inline bserial_status_t
buxn_dbgx_str(
	bserial_ctx_t* ctx,
	char** buf_ptr,
	char* buf_ptr_max,
	const char** str_ptr
) {
	if (bserial_mode(ctx) == BSERIAL_MODE_READ) {
		if (*buf_ptr >= buf_ptr_max - 1) { return BSERIAL_MALFORMED; }

		uint64_t len = buf_ptr_max - *buf_ptr;
		BSERIAL_CHECK_STATUS(bserial_blob(ctx, *buf_ptr, &len));
		if (len > 0) {
			(*buf_ptr)[len] = '\0';
			*str_ptr = *buf_ptr;
			*buf_ptr += len + 1;
		} else {
			*str_ptr = NULL;
		}
	} else {
		uint64_t len = *str_ptr != NULL ? strlen(*str_ptr) : 0;
		BSERIAL_CHECK_STATUS(bserial_blob(ctx, (char*)*str_ptr, &len));
	}

	return BSERIAL_OK;
}

bserial_status_t
buxn_dbgx_protocol_msg_header(bserial_ctx_t* ctx, buxn_dbgx_msg_t* msg) {
	uint8_t type = msg->type;
	BSERIAL_CHECK_STATUS(bserial_any_int(ctx, &type));
	msg->type = type;
	return BSERIAL_OK;
}

bserial_status_t
buxn_dbgx_protocol_msg_body(
	bserial_ctx_t* ctx,
	buxn_dbg_msg_buffer_t buffer,
	buxn_dbgx_msg_t* msg
) {
	uint8_t type = msg->type;
	char* str_buf = (char*)buffer;
	char* str_buf_max = buffer == NULL
		? NULL
		: (char*)buffer + BUXN_DBG_MAX_MEM_ACCESS_SIZE;
	switch ((buxn_dbgx_msg_type_t)type) {
		case BUXN_DBGX_MSG_INIT: {
			BSERIAL_RECORD(ctx, &msg->init) {
				BSERIAL_KEY(ctx, client_name) {
					BSERIAL_CHECK_STATUS(
						buxn_dbgx_str(ctx, &str_buf, str_buf_max, &msg->init.client_name)
					);
				}
			};
		} break;
		case BUXN_DBGX_MSG_BYE:
			break;
		case BUXN_DBGX_MSG_CORE:
			BSERIAL_CHECK_STATUS(buxn_dbg_protocol_msg(ctx, buffer, &msg->core));
			break;
		case BUXN_DBGX_MSG_LOG: {
			BSERIAL_RECORD(ctx, &msg->log) {
				BSERIAL_KEY(ctx, level) {
					BSERIAL_CHECK_STATUS(bserial_any_int(ctx, &msg->log.level));
				}
				BSERIAL_KEY(ctx, coro_name) {
					BSERIAL_CHECK_STATUS(
						buxn_dbgx_str(ctx, &str_buf, str_buf_max, &msg->log.coro_name)
					);
				}
				BSERIAL_KEY(ctx, file) {
					BSERIAL_CHECK_STATUS(
						buxn_dbgx_str(ctx, &str_buf, str_buf_max, &msg->log.file)
					);
				}
				BSERIAL_KEY(ctx, line) {
					BSERIAL_CHECK_STATUS(bserial_any_int(ctx, &msg->log.line));
				}
				BSERIAL_KEY(ctx, msg) {
					BSERIAL_CHECK_STATUS(
						buxn_dbgx_str(ctx, &str_buf, str_buf_max, &msg->log.msg)
					);
				}
			}
		} break;
		case BUXN_DBGX_MSG_INFO_REQ:
			if (bserial_mode(ctx) == BSERIAL_MODE_READ) {
				msg->info = buxn_dbgx_protocol_alloc(buffer, _Alignof(buxn_dbgx_info_t));
			}
			break;
		case BUXN_DBGX_MSG_INFO_REP:
			BSERIAL_RECORD(ctx, msg->info) {
				BSERIAL_KEY(ctx, "vector_addr") {
					BSERIAL_CHECK_STATUS(bserial_any_int(ctx, &msg->info->vector_addr));
				}
				BSERIAL_KEY(ctx, "pc") {
					BSERIAL_CHECK_STATUS(bserial_any_int(ctx, &msg->info->pc));
				}
				BSERIAL_KEY(ctx, "brkp_id") {
					BSERIAL_CHECK_STATUS(bserial_any_int(ctx, &msg->info->brkp_id));
				}
				BSERIAL_KEY(ctx, "vm_executing") {
					BSERIAL_CHECK_STATUS(bserial_bool(ctx, &msg->info->vm_executing));
				}
				BSERIAL_KEY(ctx, "vm_paused") {
					BSERIAL_CHECK_STATUS(bserial_bool(ctx, &msg->info->vm_paused));
				}
				BSERIAL_KEY(ctx, "focus") {
					BSERIAL_CHECK_STATUS(bserial_any_int(ctx, &msg->info->focus));
				}
			}
			break;
		case BUXN_DBGX_MSG_SET_FOCUS:
			BSERIAL_RECORD(ctx, &msg->set_focus) {
				BSERIAL_KEY(ctx, "address") {
					BSERIAL_CHECK_STATUS(bserial_any_int(ctx, &msg->set_focus.address));
				}
			}
			break;
	}

	return BSERIAL_OK;
}
