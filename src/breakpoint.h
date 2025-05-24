#ifndef BUXN_DBG_BREAKPOINT_H
#define BUXN_DBG_BREAKPOINT_H

#include <buxn/dbg/core.h>
#include <buxn/dbg/symbol.h>
#include "client.h"

typedef struct {
	uint8_t nbrkps;
	buxn_dbg_brkp_t brkps[255];
} buxn_brkp_set_t;

void
buxn_brkp_set_update(buxn_brkp_set_t* brkp_set, uint8_t id, buxn_dbg_brkp_t brkp);

const buxn_dbg_brkp_t*
buxn_brkp_set_find(const buxn_brkp_set_t* brkp_set, uint16_t addr);

bio_call_status_t
buxn_brkp_toggle(
	buxn_dbg_client_t client,
	buxn_brkp_set_t* brkp_set,
	uint16_t addr, uint8_t mask,
	const buxn_dbg_sym_t* sym
);

bio_call_status_t
buxn_brkp_set_load(buxn_brkp_set_t* brkp_set, buxn_dbg_client_t client);

#endif
