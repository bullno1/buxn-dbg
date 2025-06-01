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

	bserial_file_io_t io;
	bserial_file_io_init(&io, dbg_file);
	buxn_dbg_symtab_reader_opts_t reader_opts = { .input = &io.in };
	buxn_dbg_symtab_reader_t* reader = buxn_dbg_make_symtab_reader(
		buxn_dbg_malloc(buxn_dbg_symtab_reader_mem_size(&reader_opts)),
		&reader_opts
	);

	buxn_dbg_symtab_io_status_t status = buxn_dbg_read_symtab_header(reader);
	if (status != BUXN_DBG_SYMTAB_OK) {
		BIO_ERROR("Error while loading symbols");
		goto end;
	}

	symtab = buxn_dbg_malloc(buxn_dbg_symtab_mem_size(reader));
	status = buxn_dbg_read_symtab(reader, symtab);
end:
	if (status != BUXN_DBG_SYMTAB_OK) {
		buxn_dbg_free(symtab);
		symtab = NULL;
	}

	buxn_dbg_free(reader);
	bio_fclose(dbg_file, NULL);

	return symtab;
}

void
buxn_dbg_unload_symbols(buxn_dbg_symtab_t* symtab) {
	buxn_dbg_free(symtab);
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
	uint32_t index = (uint32_t)*index_hint;
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
