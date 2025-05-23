#ifndef BUXN_DBGX_LOGGER_H
#define BUXN_DBGX_LOGGER_H

#include <bio/bio.h>
#include <bserial.h>
#include "btmp_buf.h"

#define BUXN_DBG_LOG_SOCKET "@buxn/log"

static const bserial_ctx_config_t buxn_log_bserial_config = {
	.max_symbol_len = 7,
	.max_num_symbols = 5,
	.max_record_fields = 5,
	.max_depth = 3,
};

typedef struct {
	const char* coro;
	bio_log_level_t level;
	const char* file;
	int line;
	const char* content;
} buxn_dbg_log_msg_t;

bserial_status_t
buxn_dbg_serialize_log_msg(
	bserial_ctx_t* bserial,
	buxn_dbg_log_msg_t* msg,
	btmp_buf_t* tmp_buf
);

bio_logger_t
buxn_dbg_add_net_logger(bio_log_level_t min_level);

#endif
