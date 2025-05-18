#ifndef BUXN_DBG_COMMON_H
#define BUXN_DBG_COMMON_H

#include <bio/net.h>
#include <bio/file.h>
#include <buxn/dbg/core.h>
#include <buxn/dbg/protocol.h>
#include <bserial.h>

#define BUXN_CONTAINER_OF(ptr, type, member) \
	((type *)((char *)(1 ? (ptr) : &((type *)0)->member) - offsetof(type, member)))

typedef int (*bio_entry_fn_t)(void* userdata);

typedef enum {
	BUXN_DBG_TRANSPORT_FILE,
	BUXN_DBG_TRANSPORT_NET_CONNECT,
	BUXN_DBG_TRANSPORT_NET_LISTEN,
} buxn_dbg_transport_type_t;

typedef struct {
	buxn_dbg_transport_type_t type;

	union {
		struct {
			bio_addr_t addr;
			bio_port_t port;
		} net;
		const char* file;
	};
} buxn_dbg_transport_info_t;

typedef enum {
	BUXN_DBGX_MSG_CORE   = 0,
	BUXN_DBGX_MSG_FOCUS  = 1,
	BUXN_DBGX_MSG_LOG    = 2,
} buxn_dbgx_msg_type_t;

typedef enum {
	BUXN_DBGP_FOCUS_HOVER    = 0,
	BUXN_DBGP_FOCUS_CURRENT  = 1,
} buxn_dbgp_focus_type_t;

typedef struct {
	buxn_dbgx_msg_type_t type;
	union {
		buxn_dbg_msg_t core;

		struct {
			buxn_dbgp_focus_type_t type;
			uint16_t address;
		} focus;

		struct {
			bio_log_level_t level;
			int line;
			const char* file;
			const char* msg;
		} log;
	};
} buxn_dbgx_msg_t;

typedef struct {
	bserial_in_t in;
	bserial_out_t out;
	bio_file_t file;
} bserial_file_io_t;

typedef struct {
	bserial_in_t in;
	bserial_out_t out;
	bio_socket_t socket;
} bserial_socket_io_t;

typedef struct {
	bserial_ctx_t* in;
	bserial_ctx_t* out;
} bserial_io_t;

void*
buxn_dbg_realloc(void* ptr, size_t size);

void*
buxn_dbg_malloc(size_t size);

void
buxn_dbg_free(void* ptr);

bool
buxn_dbg_parse_transport(const char* str, buxn_dbg_transport_info_t* info);

int
bio_enter(bio_entry_fn_t entry, void* userdata);

void
bserial_file_io_init(bserial_file_io_t* io, bio_file_t file);

void
bserial_socket_io_init(bserial_socket_io_t* io, bio_socket_t socket);

bserial_status_t
buxn_dbgx_protocol_msg_header(bserial_ctx_t* ctx, buxn_dbgx_msg_t* msg);

bserial_status_t
buxn_dbgx_protocol_msg_body(
	bserial_ctx_t* ctx,
	buxn_dbg_msg_buffer_t buffer,
	buxn_dbgx_msg_t* msg
);

static inline bserial_status_t
buxn_dbgx_protocol_msg(
	bserial_ctx_t* ctx,
	buxn_dbg_msg_buffer_t buffer,
	buxn_dbgx_msg_t* msg
) {
	BSERIAL_CHECK_STATUS(buxn_dbgx_protocol_msg_header(ctx, msg));
	BSERIAL_CHECK_STATUS(buxn_dbgx_protocol_msg_body(ctx, buffer, msg));
	return BSERIAL_OK;
}

bserial_io_t*
buxn_dbg_make_bserial_io_from_socket(bio_socket_t socket);

void
buxn_dbg_destroy_bserial_io(bserial_io_t* io);

#endif
