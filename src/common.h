#ifndef BUXN_DBG_COMMON_H
#define BUXN_DBG_COMMON_H

#include <bio/net.h>
#include <bio/buffering.h>
#include <bserial.h>
#include "barg.h"
#include "btmp_buf.h"

#define BUXN_PROTOCOL_BUF_SIZE 16384

#define CONNECT_TRANSPORT_OPT_DESC \
	"Default value: abstract-connect:buxn/dbg\n" \
	"Available transports:\n\n" \
	"* tcp-connect:<address>:<port>: Connect to an address\n" \
	"* unix-connect:<name>: Connect to a unix domain socket\n" \
	"* abstract-connect:<name>: Connect to an abstract socket\n" \

#define LOG_LEVEL_OPT_DESC \
	"Default level: info\n" \
	"Valid levels:\n\n" \
	"* trace\n" \
	"* debug\n" \
	"* info\n" \
	"* warn\n" \
	"* error\n" \
	"* fatal\n"

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
	bio_io_buffer_t in_buf;
	bio_io_buffer_t out_buf;
	bool sent_to_flush;
	bool out_buf_locked;
	bio_signal_t flush_wait_signal;
} bserial_buffer_io_t;

typedef struct {
	bserial_ctx_t* in;
	bserial_ctx_t* out;
	bserial_buffer_io_t* buffer;
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
bserial_buffer_io_init(
	bserial_buffer_io_t* io,
	bio_io_buffer_t in_buf,
	bio_io_buffer_t out_buf
);

void
bserial_buffer_io_cleanup(bserial_buffer_io_t* io);

bserial_status_t
bserial_str(bserial_ctx_t* ctx, const char** str_ptr, btmp_buf_t* tmp_buf);

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

barg_opt_t
barg_connect_opt(buxn_dbg_transport_info_t* transport);

#endif
