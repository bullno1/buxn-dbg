#ifndef BUXN_DBG_COMMON_H
#define BUXN_DBG_COMMON_H

#include <bio/net.h>
#include <bio/file.h>
#include <bserial.h>
#include "barg.h"

#define BUXN_CONTAINER_OF(ptr, type, member) \
	((type *)((char *)(1 ? (ptr) : &((type *)0)->member) - offsetof(type, member)))

typedef int (*bio_entry_fn_t)(void* userdata);

typedef enum {
	BUXN_DBG_TRANSPORT_FILE,
	BUXN_DBG_TRANSPORT_NET_CONNECT,
	BUXN_DBG_TRANSPORT_NET_LISTEN,
} buxn_dbg_transport_type_t;

typedef struct buxn_dbg_transport_info_s {
	buxn_dbg_transport_type_t type;

	union {
		struct {
			bio_addr_t addr;
			bio_port_t port;
		} net;
		const char* file;
	};
} buxn_dbg_transport_info_t;

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
buxn_dbg_set_logger(bio_logger_t logger);

void
bserial_file_io_init(bserial_file_io_t* io, bio_file_t file);

void
bserial_socket_io_init(bserial_socket_io_t* io, bio_socket_t socket);

bserial_io_t*
buxn_dbg_make_bserial_io_from_socket(bio_socket_t socket);

void
buxn_dbg_destroy_bserial_io(bserial_io_t* io);

barg_opt_parser_t
barg_transport(buxn_dbg_transport_info_t* out);

barg_opt_parser_t
barg_connect_transport(buxn_dbg_transport_info_t* out);

barg_opt_parser_t
barg_listen_transport(buxn_dbg_transport_info_t* out);

barg_opt_parser_t
barg_log_level(bio_log_level_t* out);

barg_opt_t
barg_opt_hidden_help(void);

#endif
