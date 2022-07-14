/*
 * Copyright (c) 2022 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>

#include "fido.h"
#include "fido/es384.h"

static int
decode_coord(const cbor_item_t *item, void *xy, size_t xy_len)
{
	if (cbor_isa_bytestring(item) == false ||
	    cbor_bytestring_is_definite(item) == false ||
	    cbor_bytestring_length(item) != xy_len) {
		fido_log_debug("%s: cbor type", __func__);
		return (-1);
	}

	memcpy(xy, cbor_bytestring_handle(item), xy_len);

	return (0);
}

static int
decode_pubkey_point(const cbor_item_t *key, const cbor_item_t *val, void *arg)
{
	es384_pk_t *k = arg;

	if (cbor_isa_negint(key) == false ||
	    cbor_int_get_width(key) != CBOR_INT_8)
		return (0); /* ignore */

	switch (cbor_get_uint8(key)) {
	case 1: /* x coordinate */
		return (decode_coord(val, &k->x, sizeof(k->x)));
	case 2: /* y coordinate */
		return (decode_coord(val, &k->y, sizeof(k->y)));
	}

	return (0); /* ignore */
}

int
es384_pk_decode(const cbor_item_t *item, es384_pk_t *k)
{
	if (cbor_isa_map(item) == false ||
	    cbor_map_is_definite(item) == false ||
	    cbor_map_iter(item, k, decode_pubkey_point) < 0) {
		fido_log_debug("%s: cbor type", __func__);
		return (-1);
	}

	return (0);
}

es384_pk_t *
es384_pk_new(void)
{
	return (calloc(1, sizeof(es384_pk_t)));
}

void
es384_pk_free(es384_pk_t **pkp)
{
	es384_pk_t *pk;

	if (pkp == NULL || (pk = *pkp) == NULL)
		return;

	freezero(pk, sizeof(*pk));
	*pkp = NULL;
}

int
es384_pk_from_ptr(es384_pk_t *pk, const void *ptr, size_t len)
{
	const uint8_t	*p = ptr;
	EVP_PKEY	*pkey;

	if (len < sizeof(*pk))
		return (FIDO_ERR_INVALID_ARGUMENT);

	if (len == sizeof(*pk) + 1 && *p == 0x04)
		memcpy(pk, ++p, sizeof(*pk)); /* uncompressed format */
	else
		memcpy(pk, ptr, sizeof(*pk)); /* libfido2 x||y format */

	if ((pkey = es384_pk_to_EVP_PKEY(pk)) == NULL) {
		fido_log_debug("%s: es384_pk_to_EVP_PKEY", __func__);
		explicit_bzero(pk, sizeof(*pk));
		return (FIDO_ERR_INVALID_ARGUMENT);
	}

	EVP_PKEY_free(pkey);

	return (FIDO_OK);
}

EVP_PKEY *
es384_pk_to_EVP_PKEY(const es384_pk_t *k)
{
	BN_CTX		*bnctx = NULL;
	EC_KEY		*ec = NULL;
	EC_POINT	*q = NULL;
	EVP_PKEY	*pkey = NULL;
	BIGNUM		*x = NULL;
	BIGNUM		*y = NULL;
	const EC_GROUP	*g = NULL;
	int		 ok = -1;

	if ((bnctx = BN_CTX_new()) == NULL)
		goto fail;

	BN_CTX_start(bnctx);

	if ((x = BN_CTX_get(bnctx)) == NULL ||
	    (y = BN_CTX_get(bnctx)) == NULL)
		goto fail;

	if (BN_bin2bn(k->x, sizeof(k->x), x) == NULL ||
	    BN_bin2bn(k->y, sizeof(k->y), y) == NULL) {
		fido_log_debug("%s: BN_bin2bn", __func__);
		goto fail;
	}

	if ((ec = EC_KEY_new_by_curve_name(NID_secp384r1)) == NULL ||
	    (g = EC_KEY_get0_group(ec)) == NULL) {
		fido_log_debug("%s: EC_KEY init", __func__);
		goto fail;
	}

	if ((q = EC_POINT_new(g)) == NULL ||
	    EC_POINT_set_affine_coordinates_GFp(g, q, x, y, bnctx) == 0 ||
	    EC_KEY_set_public_key(ec, q) == 0) {
		fido_log_debug("%s: EC_KEY_set_public_key", __func__);
		goto fail;
	}

	if ((pkey = EVP_PKEY_new()) == NULL ||
	    EVP_PKEY_assign_EC_KEY(pkey, ec) == 0) {
		fido_log_debug("%s: EVP_PKEY_assign_EC_KEY", __func__);
		goto fail;
	}

	ec = NULL; /* at this point, ec belongs to evp */

	ok = 0;
fail:
	if (bnctx != NULL) {
		BN_CTX_end(bnctx);
		BN_CTX_free(bnctx);
	}

	if (ec != NULL)
		EC_KEY_free(ec);
	if (q != NULL)
		EC_POINT_free(q);

	if (ok < 0 && pkey != NULL) {
		EVP_PKEY_free(pkey);
		pkey = NULL;
	}

	return (pkey);
}
