/*
 * Copyright (c) 2018 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/obj_mac.h>

#include "fido.h"
#include "fido/rs256.h"

static int
decode_bignum(const cbor_item_t *item, void *ptr, size_t len)
{
	if (cbor_isa_bytestring(item) == false ||
	    cbor_bytestring_is_definite(item) == false ||
	    cbor_bytestring_length(item) != len) {
		fido_log_debug("%s: cbor type", __func__);
		return (-1);
	}

	memcpy(ptr, cbor_bytestring_handle(item), len);

	return (0);
}

static int
decode_rsa_pubkey(const cbor_item_t *key, const cbor_item_t *val, void *arg)
{
	rs256_pk_t *k = arg;

	if (cbor_isa_negint(key) == false ||
	    cbor_int_get_width(key) != CBOR_INT_8)
		return (0); /* ignore */

	switch (cbor_get_uint8(key)) {
	case 0: /* modulus */
		return (decode_bignum(val, &k->n, sizeof(k->n)));
	case 1: /* public exponent */
		return (decode_bignum(val, &k->e, sizeof(k->e)));
	}

	return (0); /* ignore */
}

int
rs256_pk_decode(const cbor_item_t *item, rs256_pk_t *k)
{
	if (cbor_isa_map(item) == false ||
	    cbor_map_is_definite(item) == false ||
	    cbor_map_iter(item, k, decode_rsa_pubkey) < 0) {
		fido_log_debug("%s: cbor type", __func__);
		return (-1);
	}

	return (0);
}

rs256_pk_t *
rs256_pk_new(void)
{
	return (calloc(1, sizeof(rs256_pk_t)));
}

void
rs256_pk_free(rs256_pk_t **pkp)
{
	rs256_pk_t *pk;

	if (pkp == NULL || (pk = *pkp) == NULL)
		return;

	freezero(pk, sizeof(*pk));
	*pkp = NULL;
}

int
rs256_pk_from_ptr(rs256_pk_t *pk, const void *ptr, size_t len)
{
	if (len < sizeof(*pk))
		return (FIDO_ERR_INVALID_ARGUMENT);

	memcpy(pk, ptr, sizeof(*pk));

	return (FIDO_OK);
}

EVP_PKEY *
rs256_pk_to_EVP_PKEY(const rs256_pk_t *k)
{
	RSA		*rsa = NULL;
	EVP_PKEY	*pkey = NULL;
	BIGNUM		*n = NULL;
	BIGNUM		*e = NULL;
	int		 ok = -1;

	if ((n = BN_new()) == NULL || (e = BN_new()) == NULL)
		goto fail;

	if (BN_bin2bn(k->n, sizeof(k->n), n) == NULL ||
	    BN_bin2bn(k->e, sizeof(k->e), e) == NULL) {
		fido_log_debug("%s: BN_bin2bn", __func__);
		goto fail;
	}

	if ((rsa = RSA_new()) == NULL || RSA_set0_key(rsa, n, e, NULL) == 0) {
		fido_log_debug("%s: RSA_set0_key", __func__);
		goto fail;
	}

	/* at this point, n and e belong to rsa */
	n = NULL;
	e = NULL;

	if ((pkey = EVP_PKEY_new()) == NULL ||
	    EVP_PKEY_assign_RSA(pkey, rsa) == 0) {
		fido_log_debug("%s: EVP_PKEY_assign_RSA", __func__);
		goto fail;
	}

	rsa = NULL; /* at this point, rsa belongs to evp */

	ok = 0;
fail:
	if (n != NULL)
		BN_free(n);
	if (e != NULL)
		BN_free(e);
	if (rsa != NULL)
		RSA_free(rsa);
	if (ok < 0 && pkey != NULL) {
		EVP_PKEY_free(pkey);
		pkey = NULL;
	}

	return (pkey);
}

int
rs256_pk_from_RSA(rs256_pk_t *pk, const RSA *rsa)
{
	const BIGNUM	*n = NULL;
	const BIGNUM	*e = NULL;
	const BIGNUM	*d = NULL;
	int		 k;

	if (RSA_bits(rsa) != 2048) {
		fido_log_debug("%s: invalid key length", __func__);
		return (FIDO_ERR_INVALID_ARGUMENT);
	}

	RSA_get0_key(rsa, &n, &e, &d);

	if (n == NULL || e == NULL) {
		fido_log_debug("%s: RSA_get0_key", __func__);
		return (FIDO_ERR_INTERNAL);
	}

	if ((k = BN_num_bytes(n)) < 0 || (size_t)k > sizeof(pk->n) ||
	    (k = BN_num_bytes(e)) < 0 || (size_t)k > sizeof(pk->e)) {
		fido_log_debug("%s: invalid key", __func__);
		return (FIDO_ERR_INTERNAL);
	}

	if ((k = BN_bn2bin(n, pk->n)) < 0 || (size_t)k > sizeof(pk->n) ||
	    (k = BN_bn2bin(e, pk->e)) < 0 || (size_t)k > sizeof(pk->e)) {
		fido_log_debug("%s: BN_bn2bin", __func__);
		return (FIDO_ERR_INTERNAL);
	}

	return (FIDO_OK);
}

int
rs256_verify_sig(const fido_blob_t *dgst, const rs256_pk_t *pk,
    const fido_blob_t *sig)
{
	EVP_PKEY	*pkey = NULL;
	RSA		*rsa = NULL;
	int		 ok = -1;

	/* RSA_verify needs unsigned ints */
	if (dgst->len > UINT_MAX || sig->len > UINT_MAX) {
		fido_log_debug("%s: dgst->len=%zu, sig->len=%zu", __func__,
		    dgst->len, sig->len);
		return (-1);
	}

	if ((pkey = rs256_pk_to_EVP_PKEY(pk)) == NULL ||
	    (rsa = EVP_PKEY_get0_RSA(pkey)) == NULL) {
		fido_log_debug("%s: pk -> ec", __func__);
		goto fail;
	}

	if (RSA_verify(NID_sha256, dgst->ptr, (unsigned int)dgst->len, sig->ptr,
	    (unsigned int)sig->len, rsa) != 1) {
		fido_log_debug("%s: RSA_verify", __func__);
		goto fail;
	}

	ok = 0;
fail:
	if (pkey != NULL)
		EVP_PKEY_free(pkey);

	return (ok);
}
