#include "logger.h"
#include "common.h"
#include <bio/net.h>
#include <bmacro.h>
#include <assert.h>
#include <string.h>

typedef struct {
	bio_socket_t sock;
	bserial_out_t bserial_out;
	size_t msg_size;
	char msg_buf[1024];
	bserial_ctx_t* bserial;
	_Alignas(max_align_t) char bserial_mem[];
} buxn_dbg_logger_data_t;

static size_t
buxn_bserial_write_msg_buf(struct bserial_out_s* out, const void* buf, size_t size) {
	buxn_dbg_logger_data_t* impl = BCONTAINER_OF(out, buxn_dbg_logger_data_t, bserial_out);
	if (impl->msg_size + size > sizeof(impl->msg_buf)) {
		return 0;
	}

	memcpy(impl->msg_buf + impl->msg_size, buf, size);
	impl->msg_size += size;
	return size;
}

static void
buxn_dbg_log_fn(void* userdata, const bio_log_ctx_t* ctx, const char* msg) {
	buxn_dbg_logger_data_t* data = userdata;
	if (ctx != NULL) {
		buxn_dbg_log_msg_t log_msg = {
			.coro = bio_get_coro_name(ctx->coro),
			.level = ctx->level,
			.file = ctx->file,
			.line = ctx->line,
			.content = msg,
		};
		data->msg_size = 0;
		buxn_dbg_serialize_log_msg(data->bserial, &log_msg, NULL);
		bio_net_send_exactly(data->sock, data->msg_buf, data->msg_size, NULL);
	} else {
		bio_net_close(data->sock, NULL);
		buxn_dbg_free(data);
	}
}

bio_logger_t
buxn_dbg_add_net_logger(bio_log_level_t min_level, const char* name) {
	bio_socket_t sock;
	bio_error_t error = { 0 };
	bio_addr_t addr = {
		.type = BIO_ADDR_NAMED,
		.named = {
			.len = sizeof(BUXN_DBG_LOG_SOCKET) - 1,
			.name = BUXN_DBG_LOG_SOCKET,
		},
	};
	if (!bio_net_connect(BIO_SOCKET_STREAM, &addr, BIO_PORT_ANY, &sock, &error)) {
		return (bio_logger_t){ 0 };
	}

	size_t bserial_mem_size = bserial_ctx_mem_size(buxn_log_bserial_config);
	buxn_dbg_logger_data_t* logger_data = buxn_dbg_malloc(
		sizeof(buxn_dbg_logger_data_t) + bserial_mem_size
	);
	*logger_data = (buxn_dbg_logger_data_t){ .sock = sock };
	logger_data->bserial_out.write = buxn_bserial_write_msg_buf;
	logger_data->bserial = bserial_make_ctx(
		logger_data->bserial_mem,
		buxn_log_bserial_config, NULL, &logger_data->bserial_out
	);

	// Send name to log server
	logger_data->msg_size = 0;
	bserial_str(logger_data->bserial, &name, NULL);
	bio_net_send_exactly(sock, logger_data->msg_buf, logger_data->msg_size, NULL);

	return bio_add_logger(min_level, buxn_dbg_log_fn, logger_data);
}

bserial_status_t
buxn_dbg_serialize_log_msg(
	bserial_ctx_t* ctx,
	buxn_dbg_log_msg_t* msg,
	btmp_buf_t* tmp_buf
) {
	uint64_t len = 5;
	BSERIAL_CHECK_STATUS(bserial_array(ctx, &len));
	if (len != 5) { return BSERIAL_MALFORMED; }

	BSERIAL_CHECK_STATUS(bserial_str(ctx, &msg->coro, tmp_buf));
	BSERIAL_CHECK_STATUS(bserial_any_int(ctx, &msg->level));
	BSERIAL_CHECK_STATUS(bserial_str(ctx, &msg->file, tmp_buf));
	BSERIAL_CHECK_STATUS(bserial_any_int(ctx, &msg->line));
	BSERIAL_CHECK_STATUS(bserial_str(ctx, &msg->content, tmp_buf));

	return bserial_status(ctx);
}
