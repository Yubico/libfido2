/*
 * Copyright (c) 2020 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <zlib.h>

#include <limits.h>

#include "fido.h"

#define FIDO_COMPRESS_BOUND (1024UL * 1024UL)

int
fido_compress(fido_blob_t *dst, const fido_blob_t *src)
{
	unsigned long in_len;
	unsigned long out_len;

	if (dst == NULL || src == NULL || src->len > FIDO_COMPRESS_BOUND)
		return (FIDO_ERR_INTERNAL);

	in_len = (unsigned long)src->len;
	out_len = compressBound(in_len);
	if ((dst->ptr = calloc(1, out_len)) == NULL)
		return (FIDO_ERR_INTERNAL);

	if (compress(dst->ptr, &out_len, src->ptr, in_len) != Z_OK)
		return (FIDO_ERR_COMPRESS);

	dst->len = (size_t)out_len;

	return (FIDO_OK);
}

int
fido_uncompress(fido_blob_t *dst, const fido_blob_t *src, size_t orig_size)
{
	unsigned long in_len;
	unsigned long out_len;

	if (dst == NULL || src == NULL || src->len > ULONG_MAX ||
	    orig_size > FIDO_COMPRESS_BOUND)
		return (FIDO_ERR_INTERNAL);

	if ((dst->ptr = calloc(1, orig_size)) == NULL)
		return (FIDO_ERR_INTERNAL);

	in_len = (unsigned long)src->len;
	out_len = (unsigned long)orig_size;

	if (uncompress(dst->ptr, &out_len, src->ptr, in_len) != Z_OK)
		return (FIDO_ERR_COMPRESS);

	dst->len = (size_t)out_len;

	return (FIDO_OK);
}
