#ifndef BUXN_DBG_TUI_SYMBOL_H
#define BUXN_DBG_TUI_SYMBOL_H

#include <buxn/dbg/symtab.h>

buxn_dbg_symtab_t*
buxn_dbg_load_symbols(const char* path);

void
buxn_dbg_unload_symbols(buxn_dbg_symtab_t* symtab);

const buxn_dbg_sym_t*
buxn_dbg_find_symbol(
	const buxn_dbg_symtab_t* symtab,
	uint16_t address,
	// Since we tend to display bytes sequentially in order, the symbols are
	// usually next to each other too and there is no need to search the entire
	// symtab.
	// Instead, start searching from the previous position.
	int* index_hint
);

#endif
