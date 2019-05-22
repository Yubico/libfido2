/*
 * Copyright (c) 2019 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

/*
 * Copyright (c) 2008, Damien Miller <djm@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <openssl/evp.h>
#include <openssl/sha.h>

#include <cbor.h>
#include <fido.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

/*
 * Build wrappers around functions of interest, and have them fail
 * in a pseudo-random manner.
 */

#define WRAP(type, name, args, retval, param, prob)	\
extern type __wrap_##name args;				\
extern type __real_##name args;				\
type __wrap_##name args {				\
	if (uniform_random(100) < (prob)) {		\
		return (retval);			\
	}						\
							\
	return (__real_##name param);			\
}

/*
 * Calculate a uniformly distributed random number less than upper_bound
 * avoiding "modulo bias".
 *
 * Uniformity is achieved by generating new random numbers until the one
 * returned is outside the range [0, 2**32 % upper_bound).  This
 * guarantees the selected random number will be inside
 * [2**32 % upper_bound, 2**32) which maps back to [0, upper_bound)
 * after reduction modulo upper_bound.
 */
static uint32_t
uniform_random(uint32_t upper_bound)
{
	uint32_t r, min;

	if (upper_bound < 2)
		return 0;

	/* 2**32 % x == (2**32 - x) % x */
	min = -upper_bound % upper_bound;

	/*
	 * This could theoretically loop forever but each retry has
	 * p > 0.5 (worst case, usually far better) of selecting a
	 * number inside the range we need, so it should rarely need
	 * to re-roll.
	 */
	for (;;) {
		r = (uint32_t)random();
		if (r >= min)
			break;
	}

	return r % upper_bound;
}

WRAP(void *,
	malloc,
	(size_t size),
	NULL,
	(size),
	1
)

WRAP(void *,
	calloc,
	(size_t nmemb, size_t size),
	NULL,
	(nmemb, size),
	1
)

WRAP(char *,
	strdup,
	(const char *s),
	NULL,
	(s),
	1
)

WRAP(EVP_CIPHER_CTX *,
	EVP_CIPHER_CTX_new,
	(void),
	NULL,
	(),
	1
)

WRAP(int, EVP_EncryptInit_ex,
	(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, ENGINE *impl,
	    const unsigned char *key, const unsigned char *iv),
	0,
	(ctx, type, impl, key, iv),
	1
)

WRAP(int,
	EVP_CIPHER_CTX_set_padding,
	(EVP_CIPHER_CTX *x, int padding),
	0,
	(x, padding),
	1
)

WRAP(int,
	EVP_EncryptUpdate,
	(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
	    const unsigned char *in, int inl),
	0,
	(ctx, out, outl, in, inl),
	1
)

WRAP(int,
	EVP_DecryptInit_ex,
	(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, ENGINE *impl,
	    const unsigned char *key, const unsigned char *iv),
	0,
	(ctx, type, impl, key, iv),
	1
)

WRAP(int,
	EVP_DecryptUpdate,
	(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
	    const unsigned char *in, int inl),
	0,
	(ctx, out, outl, in, inl),
	1
)

WRAP(int,
	SHA256_Init,
	(SHA256_CTX *c),
	0,
	(c),
	1
)

WRAP(int,
	SHA256_Update,
	(SHA256_CTX *c, const void *data, size_t len),
	0,
	(c, data, len),
	1
)

WRAP(int,
	SHA256_Final,
	(unsigned char *md, SHA256_CTX *c),
	0,
	(md, c),
	1
)

WRAP(RSA *,
	EVP_PKEY_get0_RSA,
	(EVP_PKEY *pkey),
	NULL,
	(pkey),
	1
)

WRAP(EVP_MD_CTX *,
	EVP_MD_CTX_new,
	(void),
	NULL,
	(),
	1
)

WRAP(int,
	EVP_DigestVerifyInit,
	(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx, const EVP_MD *type, ENGINE *e,
	    EVP_PKEY *pkey),
	0,
	(ctx, pctx, type, e, pkey),
	1
)

WRAP(cbor_item_t *,
	cbor_build_string,
	(const char *val),
	NULL,
	(val),
	1
)

WRAP(cbor_item_t *,
	cbor_build_bytestring,
	(cbor_data handle, size_t length),
	NULL,
	(handle, length),
	1
)

WRAP(cbor_item_t *,
	cbor_load,
	(cbor_data source, size_t source_size, struct cbor_load_result *result),
	NULL,
	(source, source_size, result),
	1
)

WRAP(cbor_item_t *,
	cbor_build_uint8,
	(uint8_t value),
	NULL,
	(value),
	1
)

WRAP(struct cbor_pair *,
	cbor_map_handle,
	(const cbor_item_t *item),
	NULL,
	(item),
	1
)

WRAP(cbor_item_t **,
	cbor_array_handle,
	(const cbor_item_t *item),
	NULL,
	(item),
	1
)

WRAP(bool,
	cbor_map_add,
	(cbor_item_t *item, struct cbor_pair pair),
	false,
	(item, pair),
	1
)

WRAP(cbor_item_t *,
	cbor_new_definite_map,
	(size_t size),
	NULL,
	(size),
	1
)

WRAP(size_t,
	cbor_serialize_alloc,
	(const cbor_item_t *item, cbor_mutable_data *buffer,
	    size_t *buffer_size),
	0,
	(item, buffer, buffer_size),
	1
)

WRAP(int,
	tx,
	(fido_dev_t *d, uint8_t cmd, const void *buf, size_t count),
	-1,
	(d, cmd, buf, count),
	1
)
