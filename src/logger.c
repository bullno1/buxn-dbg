#include "logger.h"
#include "common.h"
#include <string.h>
#include <bio/net.h>
#include <bio/mailbox.h>
#include <bio/service.h>

typedef struct {
	bool terminate;
	size_t msg_size;
	char msg_buf[1024];
} buxn_dbg_logger_msg_t;

typedef BIO_MAILBOX(buxn_dbg_logger_msg_t) buxn_dbg_log_mailbox_t;
typedef BIO_SERVICE(buxn_dbg_logger_msg_t) buxn_dbg_logger_t;

typedef struct {
	bio_socket_t sock;
} buxn_logger_args_t;

typedef struct {
	bserial_out_t bserial_out;
	buxn_dbg_logger_msg_t* current_msg;
	bserial_ctx_t* bserial;
	_Alignas(max_align_t) char bserial_mem[];
} buxn_log_cls_t;

static size_t
buxn_bserial_write_msg_buf(struct bserial_out_s* out, const void* buf, size_t size);

static void
buxn_log_init_cls(void* data) {
	buxn_log_cls_t* cls = data;
	cls->bserial_out.write = buxn_bserial_write_msg_buf;
	cls->bserial = bserial_make_ctx(cls->bserial_mem, buxn_log_bserial_config, NULL, &cls->bserial_out);
}

static bio_cls_t buxn_log_cls = {
	.size = 0,
	.init = buxn_log_init_cls,
};

static size_t
buxn_bserial_write_msg_buf(struct bserial_out_s* out, const void* buf, size_t size) {
	buxn_log_cls_t* cls = BUXN_CONTAINER_OF(out, buxn_log_cls_t, bserial_out);
	if (cls->current_msg->msg_size + size > sizeof(cls->current_msg->msg_buf)) {
		return 0;
	}

	memcpy(cls->current_msg->msg_buf + cls->current_msg->msg_size, buf, size);
	cls->current_msg->msg_size += size;
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
		cls->current_msg = &logger_msg;
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

	bio_foreach_message(msg, mailbox) {
		if (msg.terminate) { break; }
		// Write in a loop to deal with short writes
		size_t log_size = (size_t)msg.msg_size;
		const char* log_ptr = msg.msg_buf;
		while (log_size > 0) {
			size_t bytes_written = bio_net_send(args.sock, log_ptr, log_size, NULL);
			if (bytes_written == 0) { break; }

			log_size -= bytes_written;
			log_ptr += bytes_written;
		}
	}

	bio_net_close(args.sock, NULL);
}

bio_logger_t
buxn_dbg_add_net_logger(bio_log_level_t min_level) {
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
	BSERIAL_RECORD(ctx, msg) {
		BSERIAL_KEY(ctx, coro) {
			BSERIAL_CHECK_STATUS(bserial_str(ctx, &msg->coro, tmp_buf));
		}

		BSERIAL_KEY(ctx, level) {
			BSERIAL_CHECK_STATUS(bserial_any_int(ctx, &msg->level));
		}

		BSERIAL_KEY(ctx, file) {
			BSERIAL_CHECK_STATUS(bserial_str(ctx, &msg->file, tmp_buf));
		}

		BSERIAL_KEY(ctx, line) {
			BSERIAL_CHECK_STATUS(bserial_any_int(ctx, &msg->line));
		}

		BSERIAL_KEY(ctx, content) {
			BSERIAL_CHECK_STATUS(bserial_str(ctx, &msg->content, tmp_buf));
		}
	}

	return bserial_status(ctx);
}
