#include "logger.h"
#include "common.h"
#include <string.h>
#include <bio/net.h>
#include <bio/mailbox.h>
#include <bio/service.h>
#include <assert.h>

typedef struct {
	bool terminate;
	size_t msg_size;
	char msg_buf[1024];
} buxn_dbg_logger_msg_t;

typedef BIO_MAILBOX(buxn_dbg_logger_msg_t) buxn_dbg_log_mailbox_t;
typedef BIO_SERVICE(buxn_dbg_logger_msg_t) buxn_dbg_logger_t;

typedef struct {
	const char* name;
	bio_socket_t sock;
} buxn_logger_args_t;

typedef struct {
	bserial_out_t impl;
	buxn_dbg_logger_msg_t* current_msg;
} bserial_msg_out_t;

typedef struct {
	bserial_msg_out_t bserial_out;
	bserial_ctx_t* bserial;
	_Alignas(max_align_t) char bserial_mem[];
} buxn_log_cls_t;

static size_t
buxn_bserial_write_msg_buf(struct bserial_out_s* out, const void* buf, size_t size);

static void
buxn_log_init_cls(void* data) {
	buxn_log_cls_t* cls = data;
	cls->bserial_out.impl.write = buxn_bserial_write_msg_buf;
	cls->bserial = bserial_make_ctx(cls->bserial_mem, buxn_log_bserial_config, NULL, &cls->bserial_out.impl);
}

static bio_cls_t buxn_log_cls = {
	.size = 0,
	.init = buxn_log_init_cls,
};

static size_t
buxn_bserial_write_msg_buf(struct bserial_out_s* out, const void* buf, size_t size) {
	bserial_msg_out_t* impl = BUXN_CONTAINER_OF(out, bserial_msg_out_t, impl);
	if (impl->current_msg->msg_size + size > sizeof(impl->current_msg->msg_buf)) {
		return 0;
	}

	memcpy(impl->current_msg->msg_buf + impl->current_msg->msg_size, buf, size);
	impl->current_msg->msg_size += size;
	return size;
}

static void
buxn_dbg_log_fn(void* userdata, const bio_log_ctx_t* ctx, const char* msg) {
	buxn_dbg_logger_t logger = *(buxn_dbg_logger_t*)userdata;
	if (ctx == NULL) {
		buxn_dbg_logger_msg_t term_msg = { .terminate = true };
		bio_notify_service(logger, term_msg, true);
		bio_join(logger.coro);
		buxn_dbg_free(userdata);
	} else {
		buxn_log_cls_t* cls = bio_get_cls(&buxn_log_cls);
		buxn_dbg_logger_msg_t logger_msg = { 0 };
		cls->bserial_out.current_msg = &logger_msg;
		buxn_dbg_log_msg_t log_msg = {
			.coro = bio_get_coro_name(bio_current_coro()),
			.level = ctx->level,
			.file = ctx->file,
			.line = ctx->line,
			.content = msg,
		};
		buxn_dbg_serialize_log_msg(cls->bserial, &log_msg, NULL);
		bio_notify_service(logger, logger_msg, true);
	}
}

static void
buxn_dbg_logger_entry(void* userdata) {
	buxn_logger_args_t args;
	buxn_dbg_log_mailbox_t mailbox;
	bio_get_service_info(userdata, &mailbox, &args);

	// Send name to log server
	{
		_Alignas(max_align_t) char tmp_buf[1024];
		size_t size = bserial_ctx_mem_size(buxn_log_bserial_config);
		(void)size;
		assert(size <= sizeof(tmp_buf));
		buxn_dbg_logger_msg_t name_msg = { 0 };
		bserial_msg_out_t msg_out = {
			.impl.write = buxn_bserial_write_msg_buf,
			.current_msg = &name_msg,
		};
		bserial_ctx_t* ctx = bserial_make_ctx(tmp_buf, buxn_log_bserial_config, NULL, &msg_out.impl);
		bserial_str(ctx, &args.name, NULL);

		bio_net_send_exactly(args.sock, name_msg.msg_buf, name_msg.msg_size, NULL);
	}

	bio_foreach_message(msg, mailbox) {
		if (msg.terminate) { break; }

		bio_error_t error = { 0 };
		bio_net_send_exactly(args.sock, msg.msg_buf, msg.msg_size, &error);
		if (bio_has_error(&error)) { break; }
	}

	bio_net_close(args.sock, NULL);
}

bio_logger_t
buxn_dbg_add_net_logger(bio_log_level_t min_level, const char* name) {
	if (buxn_log_cls.size == 0) {
		buxn_log_cls.size = sizeof(buxn_log_cls_t) + bserial_ctx_mem_size(buxn_log_bserial_config);
	}

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

	buxn_dbg_logger_t logger;
	buxn_logger_args_t args = {
		.sock = sock,
		.name = name,
	};
	bio_start_service(&logger, buxn_dbg_logger_entry, args, 16);

	buxn_dbg_logger_t* log_fn_data = buxn_dbg_malloc(sizeof(buxn_dbg_logger_t));
	*log_fn_data = logger;
	return bio_add_logger(min_level, buxn_dbg_log_fn, log_fn_data);
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
