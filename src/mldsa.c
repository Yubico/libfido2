/*
 * Copyright (c) 2026 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <openssl/core_names.h>
#include <openssl/evp.h>

#include "fido.h"
#include "fido/mldsa.h"

mldsa44_pk_t *
mldsa44_pk_new(void)
{
	return calloc(1, sizeof(mldsa44_pk_t));
}

mldsa65_pk_t *
mldsa65_pk_new(void)
{
	return calloc(1, sizeof(mldsa65_pk_t));
}

mldsa87_pk_t *
mldsa87_pk_new(void)
{
	return calloc(1, sizeof(mldsa87_pk_t));
}

void
mldsa44_pk_free(mldsa44_pk_t **pkp)
{
	mldsa44_pk_t *pk;

	if (pkp == NULL || (pk = *pkp) == NULL)
		return;

	freezero(pk, sizeof(*pk));
	*pkp = NULL;
}

void
mldsa65_pk_free(mldsa65_pk_t **pkp)
{
	mldsa65_pk_t *pk;

	if (pkp == NULL || (pk = *pkp) == NULL)
		return;

	freezero(pk, sizeof(*pk));
	*pkp = NULL;
}

void
mldsa87_pk_free(mldsa87_pk_t **pkp)
{
	mldsa87_pk_t *pk;

	if (pkp == NULL || (pk = *pkp) == NULL)
		return;

	freezero(pk, sizeof(*pk));
	*pkp = NULL;
}

static EVP_PKEY *
mldsa_pk_to_EVP_PKEY(const char *name, const void *ptr, size_t len)
{
	EVP_PKEY *pkey;

	if ((pkey = EVP_PKEY_new_raw_public_key_ex(NULL, name, NULL, ptr, len)) == NULL) {
		fido_log_debug("%s: EVP_PKEY_new_raw_public_key (%s)", __func__,
		    name);
		return NULL;
	}
	return pkey;
}

EVP_PKEY *
mldsa44_pk_to_EVP_PKEY(const mldsa44_pk_t *k)
{
	return mldsa_pk_to_EVP_PKEY(LN_ML_DSA_44, k->pk, sizeof(k->pk));
}

EVP_PKEY *
mldsa65_pk_to_EVP_PKEY(const mldsa65_pk_t *k)
{
	return mldsa_pk_to_EVP_PKEY(LN_ML_DSA_65, k->pk, sizeof(k->pk));
}

EVP_PKEY *
mldsa87_pk_to_EVP_PKEY(const mldsa87_pk_t *k)
{
	return mldsa_pk_to_EVP_PKEY(LN_ML_DSA_87, k->pk, sizeof(k->pk));
}

static int
mldsa_pk_from_EVP_PKEY(const char *name, void *pk, size_t pksiz,
    const EVP_PKEY *pkey)
{
	size_t len;

	if (EVP_PKEY_is_a(pkey, name) != 1)
		return FIDO_ERR_INVALID_ARGUMENT;
	if (EVP_PKEY_get_raw_public_key(pkey, NULL, &len) != 1 || len != pksiz)
		return FIDO_ERR_INTERNAL;
	if (EVP_PKEY_get_raw_public_key(pkey, pk, &len) != 1 || len != pksiz)
		return FIDO_ERR_INTERNAL;

	return FIDO_OK;
}

int
mldsa44_pk_from_EVP_PKEY(mldsa44_pk_t *pk, const EVP_PKEY *pkey)
{
	return mldsa_pk_from_EVP_PKEY(LN_ML_DSA_44, pk->pk, sizeof(pk->pk), pkey);
}

int
mldsa65_pk_from_EVP_PKEY(mldsa65_pk_t *pk, const EVP_PKEY *pkey)
{
	return mldsa_pk_from_EVP_PKEY(LN_ML_DSA_65, pk->pk, sizeof(pk->pk), pkey);
}

int
mldsa87_pk_from_EVP_PKEY(mldsa87_pk_t *pk, const EVP_PKEY *pkey)
{
	return mldsa_pk_from_EVP_PKEY(LN_ML_DSA_87, pk->pk, sizeof(pk->pk), pkey);
}

static int
mldsa_pk_from_ptr(const char *name, void *dst, size_t dlen,
    const void *src, size_t slen)
{
	EVP_PKEY *pkey;

	if (slen != dlen)
		return FIDO_ERR_INVALID_ARGUMENT;
	if ((pkey = mldsa_pk_to_EVP_PKEY(name, src, slen)) == NULL)
		return FIDO_ERR_INVALID_ARGUMENT;

	memcpy(dst, src, dlen);
	return FIDO_OK;
}

int
mldsa44_pk_from_ptr(mldsa44_pk_t *pk, const void *ptr, size_t len)
{
	return mldsa_pk_from_ptr(LN_ML_DSA_44, pk->pk, sizeof(pk->pk), ptr, len);
}

int
mldsa65_pk_from_ptr(mldsa65_pk_t *pk, const void *ptr, size_t len)
{
	return mldsa_pk_from_ptr(LN_ML_DSA_65, pk->pk, sizeof(pk->pk), ptr, len);
}

int
mldsa87_pk_from_ptr(mldsa87_pk_t *pk, const void *ptr, size_t len)
{
	return mldsa_pk_from_ptr(LN_ML_DSA_87, pk->pk, sizeof(pk->pk), ptr, len);
}

static int
mldsa_verify_sig(const char *name, const fido_blob_t *msg,
    EVP_PKEY *pkey, const fido_blob_t *sig)
{
	EVP_PKEY_CTX *ctx = NULL;
	EVP_SIGNATURE *alg = NULL;
	int ok = -1;

	if (EVP_PKEY_is_a(pkey, name) != 1) {
		fido_log_debug("%s: EVP_PKEY_is_a(%s)", __func__, name);
		goto fail;
	}
	if ((ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL)) == NULL ||
	    (alg = EVP_SIGNATURE_fetch(NULL, name, NULL)) == NULL) {
	    fido_log_debug("%s: EVP_PKEY_CTX_new_from_pkey", __func__);
	    goto fail;
	}
	if (EVP_PKEY_verify_message_init(ctx, alg, NULL) != 1 ||
	    EVP_PKEY_verify(ctx, sig->ptr, sig->len, msg->ptr, msg->len) != 1) {
		fido_log_debug("%s: EVP_PKEY_verify (%s)", __func__, name);
		goto fail;
	}

	ok = 0;
fail:
	EVP_PKEY_CTX_free(ctx);
	return ok;
}

int
mldsa44_verify_sig(const fido_blob_t *msg, EVP_PKEY *pkey,
    const fido_blob_t *sig)
{
	return mldsa_verify_sig(LN_ML_DSA_44, msg, pkey, sig);
}

int
mldsa65_verify_sig(const fido_blob_t *msg, EVP_PKEY *pkey,
    const fido_blob_t *sig)
{
	return mldsa_verify_sig(LN_ML_DSA_65, msg, pkey, sig);
}

int
mldsa87_verify_sig(const fido_blob_t *msg, EVP_PKEY *pkey,
    const fido_blob_t *sig)
{
	return mldsa_verify_sig(LN_ML_DSA_87, msg, pkey, sig);
}


int
mldsa44_pk_verify_sig(const fido_blob_t *msg, const mldsa44_pk_t *pk,
    const fido_blob_t *sig)
{
	EVP_PKEY *pkey;
	int ok = -1;

	if ((pkey = mldsa44_pk_to_EVP_PKEY(pk)) == NULL ||
	    mldsa44_verify_sig(msg, pkey, sig) != 0) {
		fido_log_debug("%s: mldsa44_verify_sig", __func__);
		goto fail;
	}

	ok = 0;

fail:
	EVP_PKEY_free(pkey);
	return ok;
}

int
mldsa65_pk_verify_sig(const fido_blob_t *msg, const mldsa65_pk_t *pk,
    const fido_blob_t *sig)
{
	EVP_PKEY *pkey;
	int ok = -1;

	if ((pkey = mldsa65_pk_to_EVP_PKEY(pk)) == NULL ||
	    mldsa65_verify_sig(msg, pkey, sig) != 0) {
		fido_log_debug("%s: mldsa65_verify_sig", __func__);
		goto fail;
	}

	ok = 0;

fail:
	EVP_PKEY_free(pkey);
	return ok;
}

int
mldsa87_pk_verify_sig(const fido_blob_t *msg, const mldsa87_pk_t *pk,
    const fido_blob_t *sig)
{
	EVP_PKEY *pkey;
	int ok = -1;

	if ((pkey = mldsa87_pk_to_EVP_PKEY(pk)) == NULL ||
	    mldsa87_verify_sig(msg, pkey, sig) != 0) {
		fido_log_debug("%s: mldsa87_verify_sig", __func__);
		goto fail;
	}

	ok = 0;

fail:
	EVP_PKEY_free(pkey);
	return ok;
}

static int
decode_pubkey(const cbor_item_t *key, const cbor_item_t *val, void *arg)
{
	fido_blob_t *blob = arg;

	if (cbor_isa_negint(key) == false ||
	    cbor_int_get_width(key) != CBOR_INT_8)
		return (0); /* ignore */

	switch (cbor_get_uint8(key)) {
	case 0: /* akp pub */
	    return fido_blob_decode(val, blob);
	}

	return (0); /* ignore */
}

static int
mldsa_pk_decode(const cbor_item_t *item, void *ptr, size_t len)
{
	fido_blob_t pk;
	int ok = -1;

	memset(&pk, 0, sizeof(pk));

	if (cbor_isa_map(item) == false ||
	    cbor_map_is_definite(item) == false ||
	    cbor_map_iter(item, &pk, decode_pubkey) < 0 ||
	    pk.len != len) {
		fido_log_debug("%s: cbor type", __func__);
		goto fail;
	}

	memcpy(ptr, pk.ptr, len);
	ok = 0;
fail:
	fido_blob_reset(&pk);

	return ok;
}

int
mldsa44_pk_decode(const cbor_item_t *item, mldsa44_pk_t *k)
{
	return mldsa_pk_decode(item, k->pk, sizeof(k->pk));
}

int
mldsa65_pk_decode(const cbor_item_t *item, mldsa65_pk_t *k)
{
	return mldsa_pk_decode(item, k->pk, sizeof(k->pk));
}

int
mldsa87_pk_decode(const cbor_item_t *item, mldsa87_pk_t *k)
{
	return mldsa_pk_decode(item, k->pk, sizeof(k->pk));
}
