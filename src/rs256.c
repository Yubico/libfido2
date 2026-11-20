/*
 * Copyright (c) 2018-2022 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/obj_mac.h>

#include "fido.h"
#include "fido/rs256.h"
#include "openssl_compat.h"

#if defined(__GNUC__)
#define PRAGMA(s) _Pragma(s)
#else
#define PRAGMA(s)
#endif

static EVP_MD *
rs256_get_EVP_MD(void)
{
PRAGMA("GCC diagnostic push")
PRAGMA("GCC diagnostic ignored \"-Wcast-qual\"")
	return ((EVP_MD *)EVP_sha256());
PRAGMA("GCC diagnostic pop")
}

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
	EVP_PKEY *pkey;

	if (len < sizeof(*pk))
		return (FIDO_ERR_INVALID_ARGUMENT);

	memcpy(pk, ptr, sizeof(*pk));

	if ((pkey = rs256_pk_to_EVP_PKEY(pk)) == NULL) {
		fido_log_debug("%s: rs256_pk_to_EVP_PKEY", __func__);
		return (FIDO_ERR_INVALID_ARGUMENT);
	}

	EVP_PKEY_free(pkey);

	return (FIDO_OK);
}

EVP_PKEY *
rs256_pk_to_EVP_PKEY(const rs256_pk_t *k)
{
	OSSL_PARAM_BLD *bld = NULL;
	OSSL_PARAM *params = NULL;
	EVP_PKEY_CTX *ctx = NULL;
	EVP_PKEY *pkey = NULL;
	BIGNUM *modulus = NULL;
	BIGNUM *exponent = NULL;
	int ok = -1;

	if ((modulus = BN_bin2bn(k->n, sizeof(k->n), NULL)) == NULL ||
	    (exponent = BN_bin2bn(k->e, sizeof(k->e), NULL)) == NULL ||
	    BN_num_bits(modulus) != 2048 ||
	    (bld = OSSL_PARAM_BLD_new()) == NULL ||
	    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, modulus) != 1 ||
	    OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, exponent) != 1 ||
	    (params = OSSL_PARAM_BLD_to_param(bld)) == NULL ||
	    (ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL)) == NULL ||
	    EVP_PKEY_fromdata_init(ctx) != 1 ||
	    EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) != 1)
		goto done;
	ok = 0;
done:
	BN_free(modulus);
	BN_free(exponent);
	OSSL_PARAM_free(params);
	OSSL_PARAM_BLD_free(bld);
	EVP_PKEY_CTX_free(ctx);
	if (ok < 0) {
		EVP_PKEY_free(pkey);
		pkey = NULL;
	}
	return (pkey);
}

#ifndef OPENSSL_NO_DEPRECATED_3_0
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
#endif

int
rs256_pk_from_EVP_PKEY(rs256_pk_t *pk, const EVP_PKEY *pkey)
{
	BIGNUM *modulus = NULL;
	BIGNUM *exponent = NULL;
	int ok = FIDO_ERR_INVALID_ARGUMENT;

	if (EVP_PKEY_is_a(pkey, "RSA") != 1 || EVP_PKEY_get_bits(pkey) != 2048)
		goto done;
	if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &modulus) != 1 ||
	    EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &exponent) != 1 ||
	    BN_bn2binpad(modulus, pk->n, sizeof(pk->n)) != sizeof(pk->n) ||
	    BN_bn2binpad(exponent, pk->e, sizeof(pk->e)) != sizeof(pk->e)) {
		ok = FIDO_ERR_INTERNAL;
		goto done;
	}
	ok = FIDO_OK;
done:
	BN_free(modulus);
	BN_free(exponent);
	return (ok);
}

int
rs256_verify_sig(const fido_blob_t *dgst, EVP_PKEY *pkey,
    const fido_blob_t *sig)
{
	EVP_PKEY_CTX	*pctx = NULL;
	EVP_MD		*md = NULL;
	int		 ok = -1;

	if (EVP_PKEY_base_id(pkey) != EVP_PKEY_RSA) {
		fido_log_debug("%s: EVP_PKEY_base_id", __func__);
		goto fail;
	}

	if ((md = rs256_get_EVP_MD()) == NULL) {
		fido_log_debug("%s: rs256_get_EVP_MD", __func__);
		goto fail;
	}

	if ((pctx = EVP_PKEY_CTX_new(pkey, NULL)) == NULL ||
	    EVP_PKEY_verify_init(pctx) != 1 ||
	    EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING) != 1 ||
	    EVP_PKEY_CTX_set_signature_md(pctx, md) != 1) {
		fido_log_debug("%s: EVP_PKEY_CTX", __func__);
		goto fail;
	}

	if (EVP_PKEY_verify(pctx, sig->ptr, sig->len, dgst->ptr,
	    dgst->len) != 1) {
		fido_log_debug("%s: EVP_PKEY_verify", __func__);
		goto fail;
	}

	ok = 0;
fail:
	EVP_PKEY_CTX_free(pctx);

	return (ok);
}

int
rs256_pk_verify_sig(const fido_blob_t *dgst, const rs256_pk_t *pk,
    const fido_blob_t *sig)
{
	EVP_PKEY	*pkey;
	int		 ok = -1;

	if ((pkey = rs256_pk_to_EVP_PKEY(pk)) == NULL ||
	    rs256_verify_sig(dgst, pkey, sig) < 0) {
		fido_log_debug("%s: rs256_verify_sig", __func__);
		goto fail;
	}

	ok = 0;
fail:
	EVP_PKEY_free(pkey);

	return (ok);
}
