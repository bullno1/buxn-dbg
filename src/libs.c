#include "common.h"

static inline void*
buxn_dbg_blib_realloc(void* ptr, size_t size, void* ctx) {
	return buxn_dbg_realloc(ptr, size);
}

#define BLIB_REALLOC buxn_dbg_blib_realloc
#define BLIB_IMPLEMENTATION
#include <bserial.h>
#include <barray.h>
