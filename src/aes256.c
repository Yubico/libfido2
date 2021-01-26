/*
 * Copyright (c) 2018 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <openssl/evp.h>
#include <string.h>

#include "fido.h"

int
aes256_cbc_enc(const fido_dev_t *dev, const fido_blob_t *secret,
    const fido_blob_t *in, fido_blob_t *out)
{
	EVP_CIPHER_CTX	*ctx = NULL;
	unsigned char	 iv[16];
	int		 len;
	fido_blob_t	 key;
	uint8_t		 prot;
	size_t		 offset;
	int		 ok = -1;

	memset(iv, 0, sizeof(iv));
	out->ptr = NULL;
	out->len = 0;

	offset = 0;
	key.ptr = secret->ptr;
	key.len = secret->len;

	/* sanity check */
	if ((prot = fido_dev_get_pin_protocol(dev)) == 0 || key.len < 32 ||
	    in->ptr == NULL || in->len > INT_MAX || (in->len % 16) != 0) {
		fido_log_debug("%s: in->len=%zu", __func__, in->len);
		goto fail;
	}

	if (prot == CTAP_PIN_PROTOCOL2) {
		if (fido_get_random(iv, sizeof(iv)) < 0) {
			fido_log_debug("%s: fido_get_random", __func__);
			goto fail;
		}

		offset = sizeof(iv);
		key.ptr += 32;
		key.len -= 32;
	}

	if ((out->ptr = calloc(1, in->len + offset)) == NULL) {
		fido_log_debug("%s: calloc", __func__);
		goto fail;
	}

	/* may be a no-op */
	memcpy(out->ptr, iv, offset);

	if ((ctx = EVP_CIPHER_CTX_new()) == NULL || key.len != 32 ||
	    !EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.ptr, iv) ||
	    !EVP_CIPHER_CTX_set_padding(ctx, 0) ||
	    !EVP_EncryptUpdate(ctx, out->ptr + offset, &len, in->ptr, (int)in->len) ||
	    len < 0 || (size_t)len != in->len) {
		fido_log_debug("%s: EVP_Encrypt", __func__);
		goto fail;
	}

	out->len = (size_t)len + offset;

	ok = 0;
fail:
	if (ctx != NULL)
		EVP_CIPHER_CTX_free(ctx);

	if (ok < 0) {
		free(out->ptr);
		out->ptr = NULL;
		out->len = 0;
	}

	return (ok);
}

int
aes256_cbc_dec(const fido_dev_t *dev, const fido_blob_t *secret,
    const fido_blob_t *in, fido_blob_t *out)
{
	EVP_CIPHER_CTX	*ctx = NULL;
	unsigned char	 iv[16];
	int		 len;
	fido_blob_t	 key;
	uint8_t		 prot;
	size_t		 offset;
	int		 ok = -1;

	memset(iv, 0, sizeof(iv));
	out->ptr = NULL;
	out->len = 0;

	offset = 0;
	key.ptr = secret->ptr;
	key.len = secret->len;

	/* sanity check */
	if ((prot = fido_dev_get_pin_protocol(dev)) == 0 || key.len < 32 ||
	    in->ptr == NULL || in->len > INT_MAX || (in->len % 16) != 0) {
		fido_log_debug("%s: in->len=%zu", __func__, in->len);
		goto fail;
	}

	if (prot == CTAP_PIN_PROTOCOL2) {
		if (in->len < sizeof(iv)) {
			fido_log_debug("%s: not enough bytes", __func__);
			goto fail;
		}

		memcpy(iv, in->ptr, sizeof(iv));
		offset = sizeof(iv);
		key.ptr += 32;
		key.len -= 32;
	}

	if ((out->ptr = calloc(1, in->len - offset)) == NULL) {
		fido_log_debug("%s: calloc", __func__);
		goto fail;
	}

	if ((ctx = EVP_CIPHER_CTX_new()) == NULL || key.len != 32 ||
	    !EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.ptr, iv) ||
	    !EVP_CIPHER_CTX_set_padding(ctx, 0) ||
	    !EVP_DecryptUpdate(ctx, out->ptr, &len, in->ptr + offset, (int)(in->len - offset)) ||
	    len < 0 || (size_t)len > in->len + 32) {
		fido_log_debug("%s: EVP_Decrypt", __func__);
		goto fail;
	}

	out->len = (size_t)len;

	ok = 0;
fail:
	if (ctx != NULL)
		EVP_CIPHER_CTX_free(ctx);

	if (ok < 0) {
		free(out->ptr);
		out->ptr = NULL;
		out->len = 0;
	}

	return (ok);
}

int
aes256_gcm_enc(const fido_blob_t *key, const fido_blob_t *iv,
    const fido_blob_t *ad, const fido_blob_t *in, fido_blob_t *out)
{
	EVP_CIPHER_CTX	*ctx = NULL;
	int		 outlen;
	int		 ok = -1;

	if (key->len != 32 || in->ptr == NULL || in->len > INT_MAX ||
	    ad->ptr == NULL || ad->len > INT_MAX || iv->ptr == NULL ||
	    iv->len != 12) {
		fido_log_debug("%s: sanity check failed", __func__);
		goto fail;
	}

	/* tag will be appended to ciphertext */
	if ((out->ptr = calloc(1, in->len + 16)) == NULL) {
		fido_log_debug("%s: calloc", __func__);
		goto fail;
	}

	if ((ctx = EVP_CIPHER_CTX_new()) == NULL ||
	    !EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key->ptr, iv->ptr) ||
	    !EVP_EncryptUpdate(ctx, NULL, &outlen, ad->ptr, (int)ad->len) ||
	    !EVP_EncryptUpdate(ctx, out->ptr, &outlen, in->ptr, (int)in->len)) {
		fido_log_debug("%s: EVP_Encrypt", __func__);
		goto fail;
	}

	out->len = (size_t)outlen;

	if(!EVP_EncryptFinal_ex(ctx, out->ptr, &outlen) ||
	    !EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, out->ptr + out->len)) {
		fido_log_debug("%s: EVP_EncryptFinal", __func__);
		goto fail;
	}

	out->len += 16;
	ok = 0;

fail:
	if (ctx != NULL)
		EVP_CIPHER_CTX_free(ctx);

	if (ok < 0) {
		free(out->ptr);
		out->ptr = NULL;
		out->len = 0;
	}

	return (ok);
}

int
aes256_gcm_dec(const fido_blob_t *key, const fido_blob_t *iv,
    const fido_blob_t *ad, const fido_blob_t *in, fido_blob_t *out)
{
	EVP_CIPHER_CTX	*ctx = NULL;
	fido_blob_t	 ct;
	fido_blob_t	 tag;
	int		 outlen;
	int		 ok = -1;

	if (key->len != 32 || in->ptr == NULL || in->len < 16 || in->len > INT_MAX ||
	    ad->ptr == NULL || ad->len > INT_MAX || iv->ptr == NULL ||
	    iv->len != 12) {
		fido_log_debug("%s: sanity check failed", __func__);
		goto fail;
	}

	/* tag at the end of input data assumed */
	tag.len = 16;
	ct.ptr = in->ptr;
	ct.len = in->len - tag.len;
	tag.ptr = in->ptr + ct.len;

	if ((out->ptr = calloc(1, ct.len)) == NULL) {
		fido_log_debug("%s: calloc", __func__);
		goto fail;
	}

	if ((ctx = EVP_CIPHER_CTX_new()) == NULL ||
	    !EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key->ptr, iv->ptr) ||
	    !EVP_DecryptUpdate(ctx, NULL, &outlen, ad->ptr, (int)ad->len) ||
	    !EVP_DecryptUpdate(ctx, out->ptr, &outlen, ct.ptr, (int)ct.len)) {
		fido_log_debug("%s: EVP_Decrypt", __func__);
		goto fail;
	}

	/* set the plaintext length */
	out->len = (size_t)outlen;

	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, (int)tag.len, tag.ptr) ||
	    !EVP_DecryptFinal_ex(ctx, out->ptr, &outlen)) {
		fido_log_debug("%s: EVP_DecryptFinal", __func__);
		goto fail;
	}

	ok = 0;

fail:
	if (ctx != NULL)
		EVP_CIPHER_CTX_free(ctx);

	if (ok < 0) {
		free(out->ptr);
		out->ptr = NULL;
		out->len = 0;
	}

	return (ok);
}
