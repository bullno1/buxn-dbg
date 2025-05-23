#ifndef BTMP_BUF_H
#define BTMP_BUF_H

#include <stddef.h>
#include <stdint.h>

typedef struct btmp_buf_s {
	void* mem;
	size_t size;
} btmp_buf_t;

static inline void*
btmp_buf_alloc(btmp_buf_t* buf, size_t size, size_t alignment) {
	if (buf == NULL) { return NULL; }

	intptr_t buf_ptr = (intptr_t)buf->mem;
	intptr_t int_alignment = (intptr_t)alignment;
	intptr_t aligned_ptr = (buf_ptr + int_alignment - 1) & -int_alignment;
	intptr_t int_size = (intptr_t)size;
	intptr_t new_ptr = aligned_ptr + int_size;
	intptr_t buf_end = buf_ptr + (intptr_t)buf->size;
	if (new_ptr <= buf_end) {
		buf->mem = (void*)new_ptr;
		buf->size -= (size_t)(new_ptr - buf_ptr);
		return (void*)aligned_ptr;
	} else {
		return NULL;
	}
}

static inline char*
buxn_tmp_buf_alloc_str(btmp_buf_t* buf, size_t len) {
	char* str = btmp_buf_alloc(buf, len + 1, _Alignof(char));
	if (str == NULL) { return NULL; }
	str[len] = '\0';
	return str;
}

#endif
