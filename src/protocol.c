#include "protocol.h"
#include <string.h>
#include "common.h"
#include "btmp_buf.h"

bserial_status_t
buxn_dbgx_protocol_msg_header(bserial_ctx_t* ctx, buxn_dbgx_msg_t* msg) {
	uint8_t type = msg->type;
	BSERIAL_CHECK_STATUS(bserial_any_int(ctx, &type));
	msg->type = type;
	return BSERIAL_OK;
}

static bserial_status_t
buxn_dbgx_info(
	bserial_ctx_t* ctx,
	buxn_dbgx_info_t* info
) {
	BSERIAL_RECORD(ctx, info) {
		BSERIAL_KEY(ctx, "vector_addr") {
			BSERIAL_CHECK_STATUS(bserial_any_int(ctx, &info->vector_addr));
		}
		BSERIAL_KEY(ctx, "pc") {
			BSERIAL_CHECK_STATUS(bserial_any_int(ctx, &info->pc));
		}
		BSERIAL_KEY(ctx, "brkp_id") {
			BSERIAL_CHECK_STATUS(bserial_any_int(ctx, &info->brkp_id));
		}
		BSERIAL_KEY(ctx, "vm_executing") {
			BSERIAL_CHECK_STATUS(bserial_bool(ctx, &info->vm_executing));
		}
		BSERIAL_KEY(ctx, "vm_paused") {
			BSERIAL_CHECK_STATUS(bserial_bool(ctx, &info->vm_paused));
		}
		BSERIAL_KEY(ctx, "focus") {
			BSERIAL_CHECK_STATUS(bserial_any_int(ctx, &info->focus));
		}
	}

	return BSERIAL_OK;
}

static bserial_status_t
bserial_optional(bserial_ctx_t* ctx, bool* present) {
	uint64_t len = *present ? 1 : 0;
	BSERIAL_CHECK_STATUS(bserial_array(ctx, &len));
	if (len > 1) { return BSERIAL_MALFORMED; }
	*present = len > 0;
	return BSERIAL_OK;
}

bserial_status_t
buxn_dbgx_protocol_msg_body(
	bserial_ctx_t* ctx,
	buxn_dbg_msg_buffer_t buffer,
	buxn_dbgx_msg_t* msg
) {
	uint8_t type = msg->type;
	btmp_buf_t tmp_buf = {
		.mem = buffer,
		.size = buffer == NULL ? 0 : BUXN_DBG_MAX_MEM_ACCESS_SIZE,
	};
	switch ((buxn_dbgx_msg_type_t)type) {
		case BUXN_DBGX_MSG_INIT: {
			BSERIAL_RECORD(ctx, &msg->init) {
				BSERIAL_KEY(ctx, client_name) {
					BSERIAL_CHECK_STATUS(bserial_str(ctx, &msg->init.client_name, &tmp_buf));
				}

				BSERIAL_KEY(ctx, subscriptions) {
					BSERIAL_CHECK_STATUS(bserial_any_int(ctx, &msg->init.subscriptions));
				}

				BSERIAL_KEY(ctx, options) {
					BSERIAL_CHECK_STATUS(bserial_any_int(ctx, &msg->init.options));
				}
			};
		} break;
		case BUXN_DBGX_MSG_INIT_REP:
			BSERIAL_RECORD(ctx, &msg->init_rep) {
				BSERIAL_KEY(ctx, info) {
					bool present = msg->init_rep.info != NULL;
					BSERIAL_CHECK_STATUS(bserial_optional(ctx, &present));
					if (present) {
						BSERIAL_CHECK_STATUS(buxn_dbgx_info(ctx, msg->init_rep.info));
					}
				}

				BSERIAL_KEY(ctx, config) {
					bool present = msg->init_rep.config != NULL;
					BSERIAL_CHECK_STATUS(bserial_optional(ctx, &present));
					if (present) {
						BSERIAL_RECORD(ctx, msg->init_rep.config) {
							BSERIAL_KEY(ctx, dbg_filename) {
								BSERIAL_CHECK_STATUS(
									bserial_str(
										ctx,
										&msg->init_rep.config->dbg_filename,
										&tmp_buf
									)
								);
							}
							BSERIAL_KEY(ctx, src_dir) {
								BSERIAL_CHECK_STATUS(
									bserial_str(
										ctx,
										&msg->init_rep.config->src_dir,
										&tmp_buf
									)
								);
							}
						}
					}
				}
			}
			break;
		case BUXN_DBGX_MSG_BYE:
			break;
		case BUXN_DBGX_MSG_CORE:
			BSERIAL_CHECK_STATUS(buxn_dbg_protocol_msg(ctx, buffer, &msg->core));
			break;
		case BUXN_DBGX_MSG_INFO_PUSH:
			BSERIAL_CHECK_STATUS(buxn_dbgx_info(ctx, &msg->info_push));
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
