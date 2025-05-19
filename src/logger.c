#include "logger.h"
#include "common.h"

static void
buxn_dbg_log(void* userdata, const bio_log_ctx_t* ctx, const char* msg) {
	buxn_dbg_client_t* client = userdata;
	if (ctx != NULL) {
		buxn_dbg_client_send(*client, (buxn_dbgx_msg_t){
			.type = BUXN_DBGX_MSG_LOG,
			.log = {
				.level = ctx->level,
				.file = ctx->file,
				.line = ctx->line,
				.msg = msg,
			},
		});
	} else {
		buxn_dbg_free(userdata);
	}
}

bio_logger_t
buxn_dbg_add_net_logger(bio_log_level_t min_level, buxn_dbg_client_t client) {
	buxn_dbg_client_t* data = buxn_dbg_malloc(sizeof(buxn_dbg_client_t));
	*data = client;
	return bio_add_logger(min_level, buxn_dbg_log, data);
}
