#include "breakpoint.h"

void
buxn_brkp_set_update(buxn_brkp_set_t* brkp_set, uint8_t id, buxn_dbg_brkp_t brkp) {
	brkp_set->brkps[id] = brkp;
	if (brkp.mask == 0) {
		int i;
		for (i = (int)brkp_set->nbrkps - 1; i >= 0; --i) {
			if (brkp_set->brkps[i].mask != 0) {
				break;
			}
		}
		brkp_set->nbrkps = i + 1;
	} else if (id >= brkp_set->nbrkps) {
		brkp_set->nbrkps = id + 1;
	}
}

bio_call_status_t
buxn_brkp_toggle(
	buxn_dbg_client_t client,
	buxn_brkp_set_t* brkp_set,
	uint16_t addr, uint8_t mask,
	const buxn_dbg_sym_t* sym
) {
	uint8_t brkp_id = BUXN_DBG_BRKP_NONE;
	uint8_t brkp_type = mask & BUXN_DBG_BRKP_TYPE_MASK;
	for (uint8_t i = 0; i < brkp_set->nbrkps; ++i) {
		const buxn_dbg_brkp_t* brkp = &brkp_set->brkps[i];
		if (
			brkp->mask != 0
			&& brkp->addr == addr
			&& (brkp->mask & BUXN_DBG_BRKP_TYPE_MASK) == brkp_type
		) {
			brkp_id = i;
			break;
		}
	}

	if (brkp_id != BUXN_DBG_BRKP_NONE) {
		buxn_dbg_brkp_t remove = { 0 };
		buxn_brkp_set_update(brkp_set, brkp_id, remove);
		return buxn_dbg_client_send_dbg_cmd(client, (buxn_dbg_cmd_t){
			.type = BUXN_DBG_CMD_BRKP_SET,
			.brkp_set = { .id = brkp_id, .brkp = remove },
		});
	} else {
		if (sym != NULL) {
			if (sym->type == BUXN_DBG_SYM_OPCODE) {
				mask |= BUXN_DBG_BRKP_EXEC;
			} else {
				mask |= BUXN_DBG_BRKP_LOAD | BUXN_DBG_BRKP_STORE;
			}
		} else {
			mask |= BUXN_DBG_BRKP_EXEC | BUXN_DBG_BRKP_LOAD | BUXN_DBG_BRKP_STORE;
		}

		// Breakpoint 0 is reserved for "run to cursor"
		uint8_t brkp_id = brkp_set->nbrkps == 0 ? 1 : brkp_set->nbrkps;
		buxn_dbg_brkp_t brkp = { .addr = addr, .mask = mask };
		buxn_brkp_set_update(brkp_set, brkp_id, brkp);
		return buxn_dbg_client_send_dbg_cmd(client, (buxn_dbg_cmd_t){
			.type = BUXN_DBG_CMD_BRKP_SET,
			.brkp_set = { .id = brkp_id, .brkp = brkp },
		});
	}
}

const buxn_dbg_brkp_t*
buxn_brkp_set_find(const buxn_brkp_set_t* brkp_set, uint16_t addr, uint8_t mem_or_device) {
	for (uint8_t i = 0; i < brkp_set->nbrkps; ++i) {
		const buxn_dbg_brkp_t* brkp = &brkp_set->brkps[i];
		if (
			brkp->mask != 0
			&& brkp->addr == addr
			&& (brkp->mask & BUXN_DBG_BRKP_TYPE_MASK) == mem_or_device
		) {
			return brkp;
		}
	}

	return NULL;
}

bio_call_status_t
buxn_brkp_set_load(buxn_brkp_set_t* brkp_set, buxn_dbg_client_t client) {
	bio_call_status_t status = buxn_dbg_client_send_dbg_cmd(client, (buxn_dbg_cmd_t){
		.type = BUXN_DBG_CMD_INFO,
		.info = { .type = BUXN_DBG_INFO_NBRKPS, .nbrkps = &brkp_set->nbrkps },
	});
	if (status != BIO_CALL_OK) { return status; }

	for (uint8_t i = 0; i < brkp_set->nbrkps; ++i) {
		bio_call_status_t status = buxn_dbg_client_send_dbg_cmd(client, (buxn_dbg_cmd_t){
			.type = BUXN_DBG_CMD_BRKP_GET,
			.brkp_get = { .id = i, .brkp = &brkp_set->brkps[i] },
		});
		if (status != BIO_CALL_OK) { return status; }
	}

	return BIO_CALL_OK;
}
