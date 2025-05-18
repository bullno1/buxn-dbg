#include "protocol.h"
#include <string.h>

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
	switch ((buxn_dbgx_msg_type_t)type) {
		case BUXN_DBGX_MSG_CORE:
			BSERIAL_CHECK_STATUS(buxn_dbg_protocol_msg(ctx, buffer, &msg->core));
			break;
		case BUXN_DBGX_MSG_LOG: {
			char* str_buf = (char*)buffer;
			BSERIAL_RECORD(ctx, &msg->log) {
				BSERIAL_KEY(ctx, level) {
					BSERIAL_CHECK_STATUS(bserial_any_int(ctx, &msg->log.level));
				}
				BSERIAL_KEY(ctx, file) {
					if (bserial_mode(ctx) == BSERIAL_MODE_READ) {
						uint64_t len = 1024;
						BSERIAL_CHECK_STATUS(bserial_blob(ctx, str_buf, &len));
						str_buf[len] = '\0';
						msg->log.file = str_buf;
						str_buf += len + 1;
					} else {
						uint64_t len = strlen(msg->log.file);
						BSERIAL_CHECK_STATUS(bserial_blob(ctx, (char*)msg->log.file, &len));
					}
				}
				BSERIAL_KEY(ctx, line) {
					BSERIAL_CHECK_STATUS(bserial_any_int(ctx, &msg->log.line));
				}
				BSERIAL_KEY(ctx, msg) {
					if (bserial_mode(ctx) == BSERIAL_MODE_READ) {
						uint64_t len = 1024;
						BSERIAL_CHECK_STATUS(bserial_blob(ctx, str_buf, &len));
						str_buf[len] = '\0';
						msg->log.msg = str_buf;
						str_buf += len + 1;
					} else {
						uint64_t len = strlen(msg->log.msg);
						BSERIAL_CHECK_STATUS(bserial_blob(ctx, (char*)msg->log.msg, &len));
					}
				}
			}
		} break;
		case BUXN_DBGX_MSG_FOCUS: {
			BSERIAL_RECORD(ctx, &msg->focus) {
				BSERIAL_KEY(ctx, type) {
					BSERIAL_CHECK_STATUS(bserial_any_int(ctx, &msg->focus.type));
				}
				BSERIAL_KEY(ctx, address) {
					BSERIAL_CHECK_STATUS(bserial_any_int(ctx, &msg->focus.address));
				}
			}
		} break;
	}

	return BSERIAL_OK;
}
