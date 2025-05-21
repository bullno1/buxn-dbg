#include "symbol.h"
#include "common.h"
#include <bio/file.h>

buxn_dbg_symtab_t*
buxn_dbg_load_symbols(const char* path) {
	bio_file_t dbg_file = { 0 };

	bio_error_t error;
	if (!bio_fopen(&dbg_file, path, "r", &error)) {
		BIO_ERROR("Error while opening symbol: " BIO_ERROR_FMT, BIO_ERROR_FMT_ARGS(&error));
		return NULL;
	}

	buxn_dbg_symtab_t* symtab = NULL;
	bserial_ctx_config_t config = buxn_dbg_sym_recommended_bserial_config();
	void* bserial_mem = buxn_dbg_malloc(bserial_ctx_mem_size(config));
	bserial_file_io_t io;
	bserial_file_io_init(&io, dbg_file);
	bserial_ctx_t* bserial = bserial_make_ctx(bserial_mem, config, &io.in, NULL);
	uint16_t num_symbols = 0;
	if (buxn_dbg_sym_table(bserial, &num_symbols) != BSERIAL_OK) {
		BIO_ERROR("Error while loading symbols");
		goto end;
	}

	symtab = buxn_dbg_malloc(
		sizeof(buxn_dbg_symtab_t) +
		sizeof(buxn_dbg_sym_t) * num_symbols
	);
	symtab->num_symbols = (int)num_symbols;
	for (uint16_t i = 0; i < num_symbols; ++i) {
		if (buxn_dbg_sym(bserial, &symtab->symbols[i]) != BSERIAL_OK) {
			BIO_ERROR("Error while loading symbols");
			buxn_dbg_free(symtab);
			symtab = NULL;
			goto end;
		}
	}

	symtab->bserial_mem = bserial_mem;
end:
	if (symtab == NULL) {
		buxn_dbg_free(bserial_mem);
	}

	bio_fclose(dbg_file, NULL);
	return symtab;
}

void
buxn_dbg_unload_symbols(buxn_dbg_symtab_t* symtab) {
	if (symtab != NULL) {
		buxn_dbg_free(symtab->bserial_mem);
		buxn_dbg_free(symtab);
	}
}

const buxn_dbg_sym_t*
buxn_dbg_find_symbol(
	const buxn_dbg_symtab_t* symtab,
	uint16_t address,
	int* index_hint
) {
	int default_index_hint = 0;
	if (index_hint == NULL) { index_hint = &default_index_hint; }

	// One location can map to multiple labels.
	// First, only consider non-labels
	int index = *index_hint;
	const buxn_dbg_sym_t* symbol = NULL;
	for (; index < symtab->num_symbols; ++index) {
		if (symtab->symbols[index].type == BUXN_DBG_SYM_LABEL) { continue; }
		if (
			symtab->symbols[index].addr_min <= address
			&& address <= symtab->symbols[index].addr_max
		) {
			symbol =  &symtab->symbols[index];
			break;
		}

		if (symtab->symbols[index].addr_min > address) {
			break;
		}
	}

	if (symbol != NULL) {
		*index_hint = index;
		return symbol;
	}

	// Then, map it to the first label we can find
	index = *index_hint;
	for (; index < symtab->num_symbols; ++index) {
		if (
			symtab->symbols[index].addr_min <= address
			&& address <= symtab->symbols[index].addr_max
		) {
			symbol =  &symtab->symbols[index];
			break;
		}

		if (symtab->symbols[index].addr_min > address) {
			break;
		}
	}

	*index_hint = index;
	return symbol;
}
