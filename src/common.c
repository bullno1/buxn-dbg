#define _GNU_SOURCE
#include "common.h"
#include <bio/bio.h>
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

bool
buxn_dbg_parse_transport(const char* str, buxn_dbg_transport_info_t* info) {
	const char* arg;
	if        ((arg = parse_flag(str, "fifo:")) != NULL) {
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

	bio_logger_t logger = bio_add_file_logger(&(bio_file_logger_options_t){
		.file = BIO_STDERR,
		.min_level = BIO_LOG_LEVEL_TRACE,
		.with_colors = true,

		.current_filename = __FILE__,
		.current_depth_in_project = 1,
	});

	entry_data->exit_code = entry_data->entry(entry_data->userdata);

	bio_remove_logger(logger);
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
	return bio_net_recv(io->socket, buf, size, NULL);
}

static size_t
bio_socket_write(struct bserial_out_s* out, const void* buf, size_t size) {
	bserial_socket_io_t* io = BUXN_CONTAINER_OF(out, bserial_socket_io_t, out);
	return bio_net_send(io->socket, buf, size, NULL);
}

void
bserial_socket_io_init(bserial_socket_io_t* io, bio_socket_t socket) {
	io->in.read = bio_socket_read;
	io->in.skip = NULL;
	io->out.write = bio_socket_write;
	io->socket = socket;
}

bserial_status_t
buxn_dbgx_protocol_msg(
	bserial_ctx_t* ctx,
	buxn_dbg_msg_buffer_t buffer,
	buxn_dbgx_msg_t* msg
) {
	uint8_t type = msg->type;
	BSERIAL_CHECK_STATUS(bserial_any_int(ctx, &type));
	msg->type = type;

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
