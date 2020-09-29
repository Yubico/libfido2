/*
 * Copyright (c) 2018 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <openssl/evp.h>
#include <openssl/sha.h>
#if defined(LIBRESSL_VERSION_NUMBER)
#include <openssl/hkdf.h>
#else
#include <openssl/kdf.h>
#endif

#include <string.h>

#include "fido.h"
#include "fido/es256.h"

#if defined(LIBRESSL_VERSION_NUMBER)
static int
hkdf_sha256(fido_blob_t *secret, char *info, uint8_t *buf, size_t len)
{
	uint8_t salt[32];

	memset(salt, 0, sizeof(salt));

	if(HKDF(buf, len, EVP_sha256(), secret->ptr, secret->len, salt, sizeof(salt),
	    (uint8_t *)info, strlen(info)) != 1)
		return (-1);

	return (0);
}
#else
static int
hkdf_sha256(fido_blob_t *secret, char *info, uint8_t *buf, size_t len)
{
	uint8_t		salt[32];
	int		ok = -1;
	EVP_PKEY_CTX	*ctx = NULL;
	const EVP_MD    *tmp = NULL;
	EVP_MD		*md = NULL;

	memset(salt, 0, sizeof(salt));

	if ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL)) == NULL ||
	    EVP_PKEY_derive_init(ctx) <= 0) {
		fido_log_debug("%s: EVP_PKEY_derive_init", __func__);
		goto fail;
	}

	if ((tmp = EVP_sha256()) == NULL ||
	    (md = EVP_MD_meth_dup(tmp)) == NULL) {
		fido_log_debug("%s: EVP_PKEY_meth_dup", __func__);
		goto fail;
	}

	if (EVP_PKEY_CTX_set_hkdf_md(ctx, md) <= 0) {
		fido_log_debug("%s: EVP_PKEY_CTX_set_hkdf_md", __func__);
		goto fail;
	}

	if (EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt, sizeof(salt)) <= 0) {
		fido_log_debug("%s: EVP_PKEY_CTX_set1_hkdf_salt", __func__);
		goto fail;
	}

	if (EVP_PKEY_CTX_set1_hkdf_key(ctx, secret->ptr, (int)secret->len) <= 0) {
		fido_log_debug("%s: EVP_PKEY_CTX_set1_hkdf_key", __func__);
		goto fail;
	}

	if (EVP_PKEY_CTX_add1_hkdf_info(ctx, info, (int)strlen(info)) <= 0) {
		fido_log_debug("%s: EVP_PKEY_CTX_add1_hkdf_info", __func__);
		goto fail;
	}

	if (EVP_PKEY_derive(ctx, buf, &len) <= 0) {
		fido_log_debug("%s: EVP_PKEY_derive", __func__);
		goto fail;
	}

	ok = 0;
fail:
	if (md != NULL)
		EVP_MD_meth_free(md);
	if (ctx != NULL)
		EVP_PKEY_CTX_free(ctx);

	return (ok);
}
#endif

static int
do_ecdh(const fido_dev_t *dev, const es256_sk_t *sk, const es256_pk_t *pk,
    fido_blob_t **ecdh)
{
	EVP_PKEY	*pk_evp = NULL;
	EVP_PKEY	*sk_evp = NULL;
	EVP_PKEY_CTX	*ctx = NULL;
	fido_blob_t	*secret = NULL;
	uint8_t		 prot;
	char		 hmac_info[] = "CTAP2 HMAC key";
	char		 aes_info[] = "CTAP2 AES key";
	int		 ok = -1;

	*ecdh = NULL;

	/* allocate blobs for secret & ecdh */
	if ((secret = fido_blob_new()) == NULL ||
	    (*ecdh = fido_blob_new()) == NULL)
		goto fail;

	/* wrap the keys as openssl objects */
	if ((pk_evp = es256_pk_to_EVP_PKEY(pk)) == NULL ||
	    (sk_evp = es256_sk_to_EVP_PKEY(sk)) == NULL) {
		fido_log_debug("%s: es256_to_EVP_PKEY", __func__);
		goto fail;
	}

	/* set ecdh parameters */
	if ((ctx = EVP_PKEY_CTX_new(sk_evp, NULL)) == NULL ||
	    EVP_PKEY_derive_init(ctx) <= 0 ||
	    EVP_PKEY_derive_set_peer(ctx, pk_evp) <= 0) {
		fido_log_debug("%s: EVP_PKEY_derive_init", __func__);
		goto fail;
	}

	/* perform ecdh */
	if (EVP_PKEY_derive(ctx, NULL, &secret->len) <= 0 ||
	    (secret->ptr = calloc(1, secret->len)) == NULL ||
	    EVP_PKEY_derive(ctx, secret->ptr, &secret->len) <= 0) {
		fido_log_debug("%s: EVP_PKEY_derive", __func__);
		goto fail;
	}

	if ((prot = fido_dev_get_pin_protocol(dev)) == 0) {
		fido_log_debug("%s: fido_dev_get_pin_protocol", __func__);
		goto fail;
	}

	if (prot == CTAP_PIN_PROTOCOL1) {
		/* use sha256 as a kdf on the resulting secret */
		(*ecdh)->len = SHA256_DIGEST_LENGTH;
		if (((*ecdh)->ptr = calloc(1, (*ecdh)->len)) == NULL ||
		    SHA256(secret->ptr, secret->len, (*ecdh)->ptr) !=
			(*ecdh)->ptr) {
			fido_log_debug("%s: sha256", __func__);
			goto fail;
		}
	} else if (prot == CTAP_PIN_PROTOCOL2) {
		/* hkdf-sha256 to create the two portions of the secret */
		(*ecdh)->len = SHA256_DIGEST_LENGTH * 2;
		if (((*ecdh)->ptr = calloc(1, (*ecdh)->len)) == NULL ||
		    hkdf_sha256(secret, hmac_info, (*ecdh)->ptr,
			SHA256_DIGEST_LENGTH) ||
		    hkdf_sha256(secret, aes_info,
			(*ecdh)->ptr + SHA256_DIGEST_LENGTH,
			SHA256_DIGEST_LENGTH)) {
			fido_log_debug("%s: hkdf", __func__);
			goto fail;
		}
	}

	ok = 0;
fail:
	if (pk_evp != NULL)
		EVP_PKEY_free(pk_evp);
	if (sk_evp != NULL)
		EVP_PKEY_free(sk_evp);
	if (ctx != NULL)
		EVP_PKEY_CTX_free(ctx);
	if (ok < 0)
		fido_blob_free(ecdh);

	fido_blob_free(&secret);

	return (ok);
}

int
fido_do_ecdh(fido_dev_t *dev, es256_pk_t **pk, fido_blob_t **ecdh)
{
	es256_sk_t	*sk = NULL; /* our private key */
	es256_pk_t	*ak = NULL; /* authenticator's public key */
	int		 r;

	*pk = NULL; /* our public key; returned */
	*ecdh = NULL; /* shared ecdh secret; returned */

	if ((sk = es256_sk_new()) == NULL || (*pk = es256_pk_new()) == NULL) {
		r = FIDO_ERR_INTERNAL;
		goto fail;
	}

	if (es256_sk_create(sk) < 0 || es256_derive_pk(sk, *pk) < 0) {
		fido_log_debug("%s: es256_derive_pk", __func__);
		r = FIDO_ERR_INTERNAL;
		goto fail;
	}

	if ((ak = es256_pk_new()) == NULL ||
	    fido_dev_authkey(dev, ak) != FIDO_OK) {
		fido_log_debug("%s: fido_dev_authkey", __func__);
		r = FIDO_ERR_INTERNAL;
		goto fail;
	}

	if (do_ecdh(dev, sk, ak, ecdh) < 0) {
		fido_log_debug("%s: do_ecdh", __func__);
		r = FIDO_ERR_INTERNAL;
		goto fail;
	}

	r = FIDO_OK;
fail:
	es256_sk_free(&sk);
	es256_pk_free(&ak);

	if (r != FIDO_OK) {
		es256_pk_free(pk);
		fido_blob_free(ecdh);
	}

	return (r);
}
