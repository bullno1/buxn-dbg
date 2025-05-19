#ifndef BUXN_DBGX_LOGGER_H
#define BUXN_DBGX_LOGGER_H

#include "client.h"

bio_logger_t
buxn_dbg_add_net_logger(bio_log_level_t min_level, buxn_dbg_client_t client);

#endif
