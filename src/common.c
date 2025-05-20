#define _GNU_SOURCE
#include "common.h"
#include <bio/bio.h>
#include <mem_layout.h>
#include <bio/logging/file.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include "bflag.h"

typedef struct {
	void* userdata;
	bio_entry_fn_t entry;
	int exit_code;
} bio_entry_data_t;

static bio_logger_t buxn_main_logger = { 0 };

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
bio_file_read(struct bserial_in_s* in, void* buf, size_t size) {
	bserial_file_io_t* io = BUXN_CONTAINER_OF(in, bserial_file_io_t, in);
	return bio_fread(io->file, buf, size, NULL);
}

static bool
bio_file_skip(struct bserial_in_s* in, size_t size) {
	bserial_file_io_t* io = BUXN_CONTAINER_OF(in, bserial_file_io_t, in);
	return bio_fseek(io->file, (int64_t)size, SEEK_CUR, NULL);
}

static size_t
bio_file_write(struct bserial_out_s* out, const void* buf, size_t size) {
	bserial_file_io_t* io = BUXN_CONTAINER_OF(out, bserial_file_io_t, out);
	return bio_fwrite(io->file, buf, size, NULL);
}

// TODO: Consider buffering for these
void
bserial_file_io_init(bserial_file_io_t* io, bio_file_t file) {
	io->in.read = bio_file_read;
	io->in.skip = bio_file_skip;
	io->out.write = bio_file_write;
	io->file = file;
}

static size_t
bio_socket_read(struct bserial_in_s* in, void* buf, size_t size) {
	bserial_socket_io_t* io = BUXN_CONTAINER_OF(in, bserial_socket_io_t, in);
	bio_error_t error = { 0 };
	size_t result = bio_net_recv(io->socket, buf, size, &error);
	if (bio_has_error(&error)) {
		BIO_ERROR(BIO_ERROR_FMT, BIO_ERROR_FMT_ARGS(&error));
	}
	return result;
}

static size_t
bio_socket_write(struct bserial_out_s* out, const void* buf, size_t size) {
	bserial_socket_io_t* io = BUXN_CONTAINER_OF(out, bserial_socket_io_t, out);
	bio_error_t error = { 0 };
	size_t result = bio_net_send(io->socket, buf, size, &error);
	if (bio_has_error(&error)) {
		BIO_ERROR(BIO_ERROR_FMT, BIO_ERROR_FMT_ARGS(&error));
	}
	return result;
}

void
bserial_socket_io_init(bserial_socket_io_t* io, bio_socket_t socket) {
	io->in.read = bio_socket_read;
	io->in.skip = NULL;
	io->out.write = bio_socket_write;
	io->socket = socket;
}

bserial_io_t*
buxn_dbg_make_bserial_io_from_socket(bio_socket_t socket) {
	bserial_ctx_config_t bserial_cfg = {
		.max_num_symbols = 16,
		.max_record_fields = 8,
		.max_symbol_len = 16,
		.max_depth = 4,
	};
	size_t bserial_mem_size = bserial_ctx_mem_size(bserial_cfg);

	// Allocate everything in one block
	mem_layout_t layout = { 0 };
	mem_layout_reserve(&layout, sizeof(bserial_io_t), _Alignof(bserial_io_t));
	ptrdiff_t socket_io_offset = mem_layout_reserve(&layout, sizeof(bserial_socket_io_t), _Alignof(bserial_socket_io_t));
	ptrdiff_t mem_in_offset = mem_layout_reserve(&layout, bserial_mem_size, _Alignof(max_align_t));
	ptrdiff_t mem_out_offset = mem_layout_reserve(&layout, bserial_mem_size, _Alignof(max_align_t));
	size_t total_size = mem_layout_size(&layout);
	void* mem = buxn_dbg_malloc(total_size);
	bserial_io_t* bserial_io = mem;
	bserial_socket_io_t* socket_io = mem_layout_locate(mem, socket_io_offset);
	bserial_socket_io_init(socket_io, socket);
	bserial_io->in = bserial_make_ctx(
		mem_layout_locate(mem, mem_in_offset),
		bserial_cfg,
		&socket_io->in,
		NULL
	);
	bserial_io->out = bserial_make_ctx(
		mem_layout_locate(mem, mem_out_offset),
		bserial_cfg,
		NULL,
		&socket_io->out
	);

	return bserial_io;
}

void
buxn_dbg_destroy_bserial_io(bserial_io_t* io) {
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
