#include "cmd.h"
#include "common.h"
#include "client.h"
#include "logger.h"
#include "bio_termbox2.h"
#include <bio/mailbox.h>

typedef struct {
	buxn_dbg_transport_info_t connect_transport;
	const char* dbg_filename;
	const char* src_dir;
} args_t;

typedef BIO_MAILBOX(struct tb_event) mailbox_t;

static void
bio_tb_callback(void* userdata, const struct tb_event* event) {
	mailbox_t mailbox = *(mailbox_t*)userdata;
	struct tb_event ev = *event;
	bio_wait_and_send_message(bio_tb_is_running(), mailbox, ev);
}

static int
bio_main(void* userdata) {
	args_t* args = userdata;

	buxn_dbg_client_t client;
	if (!buxn_dbg_make_client(
		&client,
		&args->connect_transport,
		&(buxn_dbgx_init_t){ .client_name = "view:memory" }
	)) {
		return 1;
	}
	buxn_dbg_set_logger(buxn_dbg_add_net_logger(BIO_LOG_LEVEL_TRACE, client));

	mailbox_t mailbox;
	bio_open_mailbox(&mailbox, 8);

	bio_tb_init(&(bio_tb_options_t){
		.userdata = &mailbox,
		.event_callback = bio_tb_callback,
	});

	bool should_run = true;
	while (should_run) {
		tb_clear();
		bio_tb_present();

		bio_tb_foreach_message(event, mailbox) {
			if (event.type == TB_EVENT_KEY) {
				if (
					event.key == TB_KEY_CTRL_C
					|| event.key == TB_KEY_ESC
					|| event.ch == 'q'
				) {
					should_run = false;
				}
			}
		}
	}

	bio_tb_shutdown();
	bio_close_mailbox(mailbox);

	buxn_dbg_stop_client(client);
	return 0;
}

BUXN_DBG_CMD_EX(view_memory, "view:memory", "Show a hex dump of memory") {
	args_t args;
	buxn_dbg_parse_transport("abstract-connect:buxn/dbg", &args.connect_transport);

	barg_opt_t opts[] = {
		{
			.name = "connect",
			.short_name = 'c',
			.value_name = "transport",
			.parser = barg_transport(&args.connect_transport),
			.summary = "How to connect to the debug server",
			.description = CONNECT_TRANSPORT_OPT_DESC,
		},
		barg_opt_hidden_help(),
	};
	barg_t barg = {
		.usage = "buxn-dbg view:memory [options]",
		.summary = self->description,
		.num_opts = sizeof(opts) / sizeof(opts[0]),
		.opts = opts,
	};

	barg_result_t result = barg_parse(&barg, argc, argv);
	if (result.status != BARG_OK) {
		barg_print_result(&barg, result, stderr);
		return result.status == BARG_PARSE_ERROR;
	}

	return bio_enter(bio_main, &args);
}
