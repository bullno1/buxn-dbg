#define _GNU_SOURCE
#include "common.h"
#include <bio/bio.h>
#include <mem_layout.h>
#include <bio/logging/file.h>
#include <bio/mailbox.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <bmacro.h>
#include "bflag.h"

typedef struct {
	void* userdata;
	bio_entry_fn_t entry;
	int exit_code;
} bio_entry_data_t;

static bio_logger_t buxn_main_logger = { 0 };

static bool buxn_buffer_flusher_started = false;

static BIO_MAILBOX(bserial_buffer_io_t*) buxn_buffer_flush_mailbox = { 0 };

bool
buxn_dbg_parse_transport(const char* str, buxn_dbg_transport_info_t* info) {
	const char* arg;
	if        ((arg = parse_flag(str, "file:")) != NULL) {
		*info = (buxn_dbg_transport_info_t){
			.type = BUXN_DBG_TRANSPORT_FILE,
			.file = arg,
		};
		return true;
	} else if ((arg = parse_flag(str, "unix-connect:")) != NULL) {
		size_t len = strlen(arg);
		if (len > sizeof(info->net.addr.named.name)) {
			return false;
		}

		info->type = BUXN_DBG_TRANSPORT_NET_CONNECT;
		info->net.addr.type = BIO_ADDR_NAMED;
		info->net.addr.named.len = len;
		memcpy(info->net.addr.named.name, arg, len);
		return true;
	} else if ((arg = parse_flag(str, "unix-listen:")) != NULL) {
		size_t len = strlen(arg);
		if (len > sizeof(info->net.addr.named.name)) {
			return false;
		}

		info->type = BUXN_DBG_TRANSPORT_NET_LISTEN;
		info->net.addr.type = BIO_ADDR_NAMED;
		info->net.addr.named.len = len;
		memcpy(info->net.addr.named.name, arg, len);
		return true;
	} else if ((arg = parse_flag(str, "abstract-connect:")) != NULL) {
		size_t len = strlen(arg);
		if (len >= sizeof(info->net.addr.named.name)) {
			return false;
		}

		info->type = BUXN_DBG_TRANSPORT_NET_CONNECT;
		info->net.addr.type = BIO_ADDR_NAMED;
		info->net.addr.named.len = len + 1;
		memcpy(info->net.addr.named.name + 1, arg, len);
		info->net.addr.named.name[0] = '@';
		return true;
	} else if ((arg = parse_flag(str, "abstract-listen:")) != NULL) {
		size_t len = strlen(arg);
		if (len >= sizeof(info->net.addr.named.name)) {
			return false;
		}

		info->type = BUXN_DBG_TRANSPORT_NET_LISTEN;
		info->net.addr.type = BIO_ADDR_NAMED;
		info->net.addr.named.len = len + 1;
		memcpy(info->net.addr.named.name + 1, arg, len);
		info->net.addr.named.name[0] = '@';
		return true;
	} else if ((arg = parse_flag(str, "tcp-connect:")) != NULL) {
		char buf[sizeof("255.255.255.255:65535")];

		size_t len = strlen(arg);
		if (len > sizeof(buf)) { return -1; }
		memcpy(buf, arg, len);

		int i;
		for (i = 0; i < (int)len; ++i) {
			if (buf[i] == ':') {
				buf[i] = '\0';
				break;
			}
		}
		if (i >= (int)len) { return -1; }

		struct addrinfo hints = {
			.ai_family = AF_INET,
			.ai_socktype = SOCK_STREAM,
		};
		struct addrinfo* addrinfo;
		if (getaddrinfo(buf, buf + i + 1, &hints, &addrinfo) != 0) {
			return false;
		}

		info->type = BUXN_DBG_TRANSPORT_NET_CONNECT;
		bool converted = true;
		if (addrinfo->ai_family == AF_INET) {
			info->net.addr.type = BIO_ADDR_IPV4;
			struct sockaddr_in* addr = (struct sockaddr_in*)addrinfo->ai_addr;
			memcpy(info->net.addr.ipv4, &addr->sin_addr, sizeof(info->net.addr.ipv4));
			info->net.port = ntohs(addr->sin_port);
		} else if (addrinfo->ai_family == AF_INET6) {
			info->net.addr.type = BIO_ADDR_IPV6;
			struct sockaddr_in6* addr = (struct sockaddr_in6*)addrinfo->ai_addr;
			memcpy(info->net.addr.ipv6, &addr->sin6_addr, sizeof(info->net.addr.ipv6));
			info->net.port = ntohs(addr->sin6_port);
		} else {
			converted = false;
		}

		freeaddrinfo(addrinfo);
		return converted;
	} else if ((arg = parse_flag(str, "tcp-listen:")) != NULL) {
		errno = 0;
		long port = strtol(arg, NULL, 10);
		if (errno == 0) {
			*info = (buxn_dbg_transport_info_t){
				.type = BUXN_DBG_TRANSPORT_NET_LISTEN,
				.net = {
					.addr = BIO_ADDR_IPV4_ANY,
					.port = port,
				},
			};
			return true;
		} else {
			return false;
		}
	} else {
		return false;
	}
}

static void
bio_entry_wrapper(void* userdata) {
	bio_set_coro_name("main");
	bio_entry_data_t* entry_data = userdata;

	buxn_main_logger = bio_add_file_logger(
		BIO_LOG_LEVEL_TRACE,
		&(bio_file_logger_options_t){
			.file = BIO_STDERR,
			.with_colors = true,
		}
	);

	entry_data->exit_code = entry_data->entry(entry_data->userdata);

	bio_remove_logger(buxn_main_logger);
}

// TODO: switch allocator
void*
buxn_dbg_realloc(void* ptr, size_t size) {
	if (size == 0) {
		free(ptr);
		return NULL;
	} else {
		return realloc(ptr, size);
	}
}

void*
buxn_dbg_malloc(size_t size) {
	return buxn_dbg_realloc(NULL, size);
}

void
buxn_dbg_free(void* ptr) {
	buxn_dbg_realloc(ptr, 0);
}

static void*
buxn_dbg_realloc_wrapper(void* ptr, size_t size, void* ctx) {
	(void)ctx;
	return buxn_dbg_realloc(ptr, size);
}

int
bio_enter(bio_entry_fn_t entry, void* userdata) {
	bio_init(&(bio_options_t){
		.allocator.realloc = buxn_dbg_realloc_wrapper,
		.log_options = {
			.current_filename = __FILE__,
			.current_depth_in_project = 1,
		},
		.thread_pool = {
			.num_threads = 4,
		},
	});

	bio_entry_data_t entry_data = {
		.entry = entry,
		.userdata = userdata,
	};
	bio_spawn(bio_entry_wrapper, &entry_data);

	bio_loop();

	bio_terminate();

	return entry_data.exit_code;
}

void
buxn_dbg_set_logger(bio_logger_t logger) {
	bio_remove_logger(buxn_main_logger);
	buxn_main_logger = logger;
}

static size_t
bserial_buffered_read(struct bserial_in_s* in, void* buf, size_t size) {
	bserial_buffer_io_t* io = BCONTAINER_OF(in, bserial_buffer_io_t, in);
	bio_error_t error = { 0 };
	size_t result = bio_buffered_read(io->in_buf, buf, size, &error);
	if (bio_has_error(&error)) {
		BIO_ERROR("Error while reading: " BIO_ERROR_FMT, BIO_ERROR_FMT_ARGS(&error));
	}
	return result;
}

static void
buxn_lock_buffer_io(bserial_buffer_io_t* io) {
	while (io->out_buf_locked) {
		bio_yield();
	}
	io->out_buf_locked = true;
}

static void
buxn_unlock_buffer_io(bserial_buffer_io_t* io) {
	io->out_buf_locked = false;
}

static void
buxn_buffer_flusher_exit(void* userdata) {
	bio_wait_for_exit();
	bserial_buffer_io_t* terminate = NULL;
	bio_send_message(buxn_buffer_flush_mailbox, terminate);
}

static void
buxn_buffer_flusher(void* userdata) {
	// Spawn a coroutine that will message this to exit
	bio_spawn_ex(buxn_buffer_flusher_exit, NULL, &(bio_coro_options_t){ .daemon = true });

	bio_foreach_message(io, buxn_buffer_flush_mailbox) {
		if(io == NULL) { break; }
		bio_error_t error = { 0 };

		buxn_lock_buffer_io(io);
		io->sent_to_flush = false;
		if (!bio_flush_buffer(io->out_buf, &error)) {
			BIO_ERROR("Error while flushing: " BIO_ERROR_FMT, BIO_ERROR_FMT_ARGS(&error));
		}
		buxn_unlock_buffer_io(io);
		bio_raise_signal(io->flush_wait_signal);
	}
	bio_close_mailbox(buxn_buffer_flush_mailbox);
}

static size_t
bserial_buffered_write(struct bserial_out_s* out, const void* buf, size_t size) {
	bserial_buffer_io_t* io = BCONTAINER_OF(out, bserial_buffer_io_t, out);
	bio_error_t error = { 0 };
	buxn_lock_buffer_io(io);
	size_t result = bio_buffered_write(io->out_buf, buf, size, &error);
	buxn_unlock_buffer_io(io);
	if (bio_has_error(&error)) {
		BIO_ERROR("Error while writing: " BIO_ERROR_FMT, BIO_ERROR_FMT_ARGS(&error));
		return 0;
	}

	if (!io->sent_to_flush) {
		if (!buxn_buffer_flusher_started) {
			bio_open_mailbox(&buxn_buffer_flush_mailbox, 8);
			buxn_buffer_flusher_started = true;
			bio_spawn_ex(buxn_buffer_flusher, NULL, &(bio_coro_options_t){
				.daemon = true,
			});
		}

		io->sent_to_flush = true;
		bio_send_message(buxn_buffer_flush_mailbox, io);
	}

	return result;
}

void
bserial_buffer_io_init(
	bserial_buffer_io_t* io,
	bio_io_buffer_t in_buf,
	bio_io_buffer_t out_buf
) {
	*io = (bserial_buffer_io_t){
		.in_buf = in_buf,
		.in.read = bserial_buffered_read,
		.out_buf = out_buf,
		.out.write = bserial_buffered_write,
	};
}

void
bserial_buffer_io_cleanup(bserial_buffer_io_t* io) {
	if (io->sent_to_flush) {
		io->flush_wait_signal = bio_make_signal();
		bio_wait_for_one_signal(io->flush_wait_signal);
	}
}

bserial_io_t*
buxn_dbg_make_bserial_io_from_socket(bio_socket_t socket) {
	bserial_ctx_config_t bserial_cfg = {
		.max_num_symbols = 16,
		.max_record_fields = 8,
		.max_symbol_len = 16,
		.max_depth = 8,
	};
	size_t bserial_mem_size = bserial_ctx_mem_size(bserial_cfg);

	// Allocate everything in one block
	mem_layout_t layout = { 0 };
	mem_layout_reserve(&layout, sizeof(bserial_io_t), _Alignof(bserial_io_t));
	ptrdiff_t buffer_io_offset = mem_layout_reserve(&layout, sizeof(bserial_buffer_io_t), _Alignof(bserial_buffer_io_t));
	ptrdiff_t mem_in_offset = mem_layout_reserve(&layout, bserial_mem_size, _Alignof(max_align_t));
	ptrdiff_t mem_out_offset = mem_layout_reserve(&layout, bserial_mem_size, _Alignof(max_align_t));
	size_t total_size = mem_layout_size(&layout);
	void* mem = buxn_dbg_malloc(total_size);
	bserial_io_t* bserial_io = mem;
	bserial_io->buffer = mem_layout_locate(mem, buffer_io_offset);
	bserial_buffer_io_init(
		bserial_io->buffer,
		bio_make_socket_read_buffer(socket, BUXN_PROTOCOL_BUF_SIZE),
		bio_make_socket_write_buffer(socket, BUXN_PROTOCOL_BUF_SIZE)
	);
	bserial_io->in = bserial_make_ctx(
		mem_layout_locate(mem, mem_in_offset),
		bserial_cfg,
		&bserial_io->buffer->in,
		NULL
	);
	bserial_io->out = bserial_make_ctx(
		mem_layout_locate(mem, mem_out_offset),
		bserial_cfg,
		NULL,
		&bserial_io->buffer->out
	);

	return bserial_io;
}

void
buxn_dbg_destroy_bserial_io(bserial_io_t* io) {
	bserial_buffer_io_cleanup(io->buffer);
	bio_destroy_buffer(io->buffer->in_buf);
	bio_destroy_buffer(io->buffer->out_buf);
	buxn_dbg_free(io);
}

static const char*
barg_parse_transport(void* userdata, const char* value) {
	if (buxn_dbg_parse_transport(value, userdata)) {
		return NULL;
	} else {
		return "Invalid transport";
	}
}

static const char*
barg_parse_connect_transport(void* userdata, const char* value) {
	buxn_dbg_transport_info_t transport;
	if (
		buxn_dbg_parse_transport(value, &transport)
		&& transport.type == BUXN_DBG_TRANSPORT_NET_CONNECT
	) {
		*(buxn_dbg_transport_info_t*)userdata = transport;
		return NULL;
	} else {
		return "Invalid transport";
	}
}

static const char*
barg_parse_listen_transport(void* userdata, const char* value) {
	buxn_dbg_transport_info_t transport;
	if (
		buxn_dbg_parse_transport(value, &transport)
		&& transport.type == BUXN_DBG_TRANSPORT_NET_LISTEN
	) {
		*(buxn_dbg_transport_info_t*)userdata = transport;
		return NULL;
	} else {
		return "Invalid transport";
	}
}

barg_opt_parser_t
barg_transport(buxn_dbg_transport_info_t* out) {
	return (barg_opt_parser_t){
		.userdata = out,
		.parse = barg_parse_transport,
	};
}

barg_opt_parser_t
barg_connect_transport(buxn_dbg_transport_info_t* out) {
	return (barg_opt_parser_t){
		.userdata = out,
		.parse = barg_parse_connect_transport,
	};
}

barg_opt_parser_t
barg_listen_transport(buxn_dbg_transport_info_t* out) {
	return (barg_opt_parser_t){
		.userdata = out,
		.parse = barg_parse_listen_transport,
	};
}


static const char*
barg_parse_log_level(void* userdata, const char* arg) {
	bio_log_level_t* level = userdata;
	if (strcmp(arg, "trace") == 0) {
		*level = BIO_LOG_LEVEL_TRACE;
		return NULL;
	} else if (strcmp(arg, "debug") == 0) {
		*level = BIO_LOG_LEVEL_DEBUG;
		return NULL;
	} else if (strcmp(arg, "info") == 0) {
		*level = BIO_LOG_LEVEL_INFO;
		return NULL;
	} else if (strcmp(arg, "warn") == 0) {
		*level = BIO_LOG_LEVEL_WARN;
		return NULL;
	} else if (strcmp(arg, "error") == 0) {
		*level = BIO_LOG_LEVEL_ERROR;
		return NULL;
	} else if (strcmp(arg, "fatal") == 0) {
		*level = BIO_LOG_LEVEL_FATAL;
		return NULL;
	} else {
		return "Invalid log level";
	}
}

barg_opt_parser_t
barg_log_level(bio_log_level_t* out) {
	return (barg_opt_parser_t){
		.userdata = out,
		.parse = barg_parse_log_level,
	};
}

barg_opt_t
barg_opt_hidden_help(void) {
	barg_opt_t opt = barg_opt_help();
	opt.hidden = true;
	return opt;
}

barg_opt_t
barg_connect_opt(buxn_dbg_transport_info_t* transport) {
	return (barg_opt_t){
		.name = "connect",
		.short_name = 'c',
		.value_name = "transport",
		.parser = barg_connect_transport(transport),
		.summary = "How to connect to the debug server",
		.description = CONNECT_TRANSPORT_OPT_DESC,
	};
}

bserial_status_t
bserial_str(bserial_ctx_t* ctx, const char** str_ptr, btmp_buf_t* tmp_buf) {
	if (bserial_mode(ctx) == BSERIAL_MODE_READ) {
		uint64_t len = tmp_buf->size;
		BSERIAL_CHECK_STATUS(bserial_blob_header(ctx, &len));
		char* name_buf = buxn_tmp_buf_alloc_str(tmp_buf, len);
		if (name_buf == NULL) { return BSERIAL_MALFORMED; }
		BSERIAL_CHECK_STATUS(bserial_blob_body(ctx, name_buf));
		if (len > 0) {
			*str_ptr = name_buf;
		} else {
			*str_ptr = NULL;
		}
	} else {
		char* str = (char*)*str_ptr;
		uint64_t str_len = str != NULL ? strlen(str) : 0;
		BSERIAL_CHECK_STATUS(bserial_blob(ctx, str, &str_len));
	}

	return BSERIAL_OK;
}
