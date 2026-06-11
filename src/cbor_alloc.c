/*
 * Copyright (c) 2026 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "fido.h"

#ifndef TLS
#define TLS
#endif

/*
 * cbor_load() pre-allocates storage for definite-length arrays and maps
 * sized by the element count declared in a message's CBOR header, before
 * reading any element data. The declared count is attacker-controlled and
 * is otherwise only checked for integer overflow, so a malicious or
 * malfunctioning authenticator can use a few bytes of input to make
 * cbor_load() attempt an allocation of up to FIDO_CBOR_MAX_ALLOC bytes
 * times libcbor's per-item overhead. See PJK/libcbor#418, which was closed
 * as "won't fix" in favor of consumer-side mitigation, and PJK/libcbor#422,
 * which documents cbor_set_allocs() as that mitigation (examples/
 * capped_alloc.c).
 *
 * fido_init_cbor_allocs() installs a capping allocator that bounds the
 * total size of live libcbor allocations to FIDO_CBOR_MAX_ALLOC. Once the
 * budget is exhausted, cbor_load() fails with CBOR_ERR_MEMERROR instead of
 * making an oversized allocation; libfido2's cbor_load() callers already
 * treat a NULL return as a (non-fatal) decode failure.
 *
 * cbor_set_allocs() configures a single, process-wide set of allocator
 * function pointers in libcbor; per the fido_init(3) man page, fido_init()
 * is called once per thread, so cbor_allocated is kept TLS and the budget
 * applies per-thread. This matches the per-thread budget alternative
 * suggested by PJK/libcbor#422 and assumes (as is the case throughout
 * libfido2) that a cbor_item_t allocated by cbor_load() in one thread is
 * not freed from another.
 */

#if defined(__APPLE__)
#include <malloc/malloc.h>
#define ALLOC_SIZE(ptr) malloc_size(ptr)
#elif defined(__linux__) && defined(__GLIBC__)
#include <malloc.h>
#define ALLOC_SIZE(ptr) malloc_usable_size(ptr)
#elif defined(_WIN32)
#include <malloc.h>
#define ALLOC_SIZE(ptr) _msize(ptr)
#endif

static TLS size_t cbor_allocated;

#ifdef ALLOC_SIZE

static void *
capped_malloc(size_t size)
{
	void *ptr;

	if (size > FIDO_CBOR_MAX_ALLOC - cbor_allocated)
		return NULL;
	if ((ptr = malloc(size)) != NULL)
		cbor_allocated += ALLOC_SIZE(ptr);

	return ptr;
}

static void *
capped_realloc(void *ptr, size_t size)
{
	size_t old_size = ptr != NULL ? ALLOC_SIZE(ptr) : 0;
	void *new_ptr;

	if (size > FIDO_CBOR_MAX_ALLOC - cbor_allocated + old_size)
		return NULL;
	if ((new_ptr = realloc(ptr, size)) != NULL) {
		cbor_allocated -= old_size;
		cbor_allocated += ALLOC_SIZE(new_ptr);
	}

	return new_ptr;
}

static void
capped_free(void *ptr)
{
	if (ptr != NULL)
		cbor_allocated -= ALLOC_SIZE(ptr);

	free(ptr);
}

#else /* !ALLOC_SIZE */

/*
 * No portable way to query the live size of an allocation: track only a
 * monotonically increasing high-water mark. The cap is still enforced, but
 * memory freed mid-decode is not reclaimed from the budget until
 * fido_init_cbor_allocs() is called again for a new operation.
 */

static void *
capped_malloc(size_t size)
{
	void *ptr;

	if (size > FIDO_CBOR_MAX_ALLOC - cbor_allocated)
		return NULL;
	if ((ptr = malloc(size)) != NULL)
		cbor_allocated += size;

	return ptr;
}

static void *
capped_realloc(void *ptr, size_t size)
{
	void *new_ptr;

	if (size > FIDO_CBOR_MAX_ALLOC - cbor_allocated)
		return NULL;
	if ((new_ptr = realloc(ptr, size)) != NULL)
		cbor_allocated += size;

	return new_ptr;
}

static void
capped_free(void *ptr)
{
	free(ptr);
}

#endif /* ALLOC_SIZE */

void
fido_init_cbor_allocs(void)
{
	cbor_allocated = 0;
	cbor_set_allocs(capped_malloc, capped_realloc, capped_free);
}
