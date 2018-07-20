/*
 * Copyright (c) 2018 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include <string.h>
#include "fido.h"
#include "fido/es256.h"
#include "fido/rs256.h"

static int
adjust_assert_count(const cbor_item_t *key, const cbor_item_t *val, void *arg)
{
	fido_assert_t	*assert = arg;
	uint64_t	 n;

	if (cbor_isa_uint(key) == false ||
	    cbor_int_get_width(key) != CBOR_INT_8) {
		log_debug("%s: cbor_type", __func__);
		return (-1);
	}

	/* numberOfCredentials; see section 6.2 */
	if (cbor_get_uint8(key) != 5)
		return (0); /* ignore */

	if (decode_uint64(val, &n) < 0 || n > SIZE_MAX) {
		log_debug("%s: decode_uint64", __func__);
		return (-1);
	}

	if (assert->stmt_len != 0 || assert->stmt_cnt != 1 ||
	    (size_t)n < assert->stmt_cnt) {
		log_debug("%s: stmt_len=%zu, stmt_cnt=%zu, n=%zu", __func__,
		    assert->stmt_len, assert->stmt_cnt, (size_t)n);
		return (-1);
	}

	if (fido_assert_set_count(assert, (size_t)n) != FIDO_OK) {
		log_debug("%s: fido_assert_set_count", __func__);
		return (-1);
	}

	assert->stmt_len = 0; /* XXX */

	return (0);
}

static int
parse_assert_reply(const cbor_item_t *key, const cbor_item_t *val, void *arg)
{
	fido_assert_stmt *stmt = arg;

	if (cbor_isa_uint(key) == false ||
	    cbor_int_get_width(key) != CBOR_INT_8) {
		log_debug("%s: cbor type", __func__);
		return (-1);
	}

	switch (cbor_get_uint8(key)) {
	case 1: /* credential id */
		return (decode_cred_id(val, &stmt->id));
	case 2: /* authdata */
		return (decode_assert_authdata(val, &stmt->authdata_cbor,
		    &stmt->authdata, &stmt->authdata_ext,
		    &stmt->hmac_secret_enc));
	case 3: /* signature */
		return (fido_blob_decode(val, &stmt->sig));
	case 4: /* user attributes */
		return (decode_user(val, &stmt->user));
	case 5: /* ignore */
		return (0);
	}

	return (-1);
}

static int
fido_dev_get_assert_tx(fido_dev_t *dev, fido_assert_t *assert,
    const es256_pk_t *pk, const fido_blob_t *ecdh, const char *pin)
{
	fido_blob_t	 f;
	cbor_item_t	*argv[7];
	int		 r;

	memset(argv, 0, sizeof(argv));
	memset(&f, 0, sizeof(f));

	/* do we have everything we need? */
	if (assert->rp_id == NULL || assert->cdh.ptr == NULL) {
		log_debug("%s: rp_id=%p, cdh.ptr=%p", __func__,
		    (void *)assert->rp_id, (void *)assert->cdh.ptr);
		r = FIDO_ERR_INVALID_ARGUMENT;
		goto fail;
	}

	if ((argv[0] = cbor_build_string(assert->rp_id)) == NULL ||
	    (argv[1] = fido_blob_encode(&assert->cdh)) == NULL ||
	    (argv[4] = encode_assert_options(assert->up, assert->uv)) == NULL) {
		log_debug("%s: cbor encode", __func__);
		r = FIDO_ERR_INTERNAL;
		goto fail;
	}

	/* allowed credentials */
	if (assert->allow_list.len) {
		const fido_blob_array_t *cl = &assert->allow_list;
		if ((argv[2] = encode_pubkey_list(cl)) == NULL) {
			log_debug("%s: encode_pubkey_list", __func__);
			r = FIDO_ERR_INTERNAL;
			goto fail;
		}
	}

	/* hmac-secret extension */
	if (assert->ext & FIDO_EXT_HMAC_SECRET)
		if ((argv[3] = encode_hmac_secret_param(ecdh, pk,
		    &assert->hmac_salt)) == NULL) {
			log_debug("%s: encode_hmac_secret_param", __func__);
			r = FIDO_ERR_INTERNAL;
			goto fail;
		}

	/* pin authentication */
	if (pin) {
		if (pk == NULL || ecdh == NULL) {
			log_debug("%s: pin=%p, pk=%p, ecdh=%p", __func__,
			    (const void *)pin, (const void *)pk,
			    (const void *)ecdh);
			r = FIDO_ERR_INVALID_ARGUMENT;
			goto fail;
		}
		if ((r = add_cbor_pin_params(dev, &assert->cdh, pk, ecdh, pin,
		    &argv[5], &argv[6])) != FIDO_OK) {
			log_debug("%s: add_cbor_pin_params", __func__);
			goto fail;
		}
	}

	/* frame and transmit */
	if (cbor_build_frame(CTAP_CBOR_ASSERT, argv, 7, &f) < 0 ||
	    tx(dev, CTAP_FRAME_INIT | CTAP_CMD_CBOR, f.ptr, f.len) < 0) {
		log_debug("%s: tx", __func__);
		r = FIDO_ERR_TX;
		goto fail;
	}

	r = FIDO_OK;
fail:
	for (size_t i = 0; i < 7; i++)
		if (argv[i] != NULL)
			cbor_decref(&argv[i]);

	free(f.ptr);

	return (r);
}

static int
fido_dev_get_assert_rx(fido_dev_t *dev, fido_assert_t *assert, int ms)
{
	const uint8_t	cmd = CTAP_FRAME_INIT | CTAP_CMD_CBOR;
	unsigned char	reply[2048];
	int		reply_len;
	int		r;

	fido_assert_reset_rx(assert);

	if ((reply_len = rx(dev, cmd, &reply, sizeof(reply), ms)) < 0) {
		log_debug("%s: rx", __func__);
		return (FIDO_ERR_RX);
	}

	/* start with room for a single assertion */
	if ((assert->stmt = calloc(1, sizeof(fido_assert_stmt))) == NULL)
		return (FIDO_ERR_INTERNAL);

	assert->stmt_len = 0;
	assert->stmt_cnt = 1;

	/* adjust as needed */
	if ((r = parse_cbor_reply(reply, (size_t)reply_len, assert,
	    adjust_assert_count)) != FIDO_OK) {
		log_debug("%s: adjust_assert_count", __func__);
		return (r);
	}

	/* parse the first assertion */
	if ((r = parse_cbor_reply(reply, (size_t)reply_len,
	    &assert->stmt[assert->stmt_len], parse_assert_reply)) != FIDO_OK) {
		log_debug("%s: parse_assert_reply", __func__);
		return (r);
	}

	assert->stmt_len++;

	return (FIDO_OK);
}

static int
fido_get_next_assert_tx(fido_dev_t *dev)
{
	const unsigned char	cbor[] = { CTAP_CBOR_NEXT_ASSERT };
	const uint8_t		cmd = CTAP_FRAME_INIT | CTAP_CMD_CBOR;

	if (tx(dev, cmd, cbor, sizeof(cbor)) < 0) {
		log_debug("%s: tx", __func__);
		return (FIDO_ERR_TX);
	}

	return (FIDO_OK);
}

static int
fido_get_next_assert_rx(fido_dev_t *dev, fido_assert_t *assert, int ms)
{
	const uint8_t	cmd = CTAP_FRAME_INIT | CTAP_CMD_CBOR;
	unsigned char	reply[2048];
	int		reply_len;
	int		r;

	if ((reply_len = rx(dev, cmd, &reply, sizeof(reply), ms)) < 0) {
		log_debug("%s: rx", __func__);
		return (FIDO_ERR_RX);
	}

	/* sanity check */
	if (assert->stmt_len >= assert->stmt_cnt) {
		log_debug("%s: stmt_len=%zu, stmt_cnt=%zu", __func__,
		    assert->stmt_len, assert->stmt_cnt);
		return (FIDO_ERR_INTERNAL);
	}

	if ((r = parse_cbor_reply(reply, (size_t)reply_len,
	    &assert->stmt[assert->stmt_len], parse_assert_reply)) != FIDO_OK) {
		log_debug("%s: parse_assert_reply", __func__);
		return (r);
	}

	return (FIDO_OK);
}

static int
fido_dev_get_assert_wait(fido_dev_t *dev, fido_assert_t *assert,
    const es256_pk_t *pk, const fido_blob_t *ecdh, const char *pin, int ms)
{
	int r;

	if ((r = fido_dev_get_assert_tx(dev, assert, pk, ecdh, pin)) != FIDO_OK ||
	    (r = fido_dev_get_assert_rx(dev, assert, ms)) != FIDO_OK)
		return (r);

	while (assert->stmt_len < assert->stmt_cnt) {
		if ((r = fido_get_next_assert_tx(dev)) != FIDO_OK ||
		    (r = fido_get_next_assert_rx(dev, assert, ms)) != FIDO_OK)
			return (r);
		assert->stmt_len++;
	}

	return (FIDO_OK);
}

static int
decrypt_hmac_secrets(fido_assert_t *assert, const fido_blob_t *key)
{
	for (size_t i = 0; i < assert->stmt_cnt; i++) {
		fido_assert_stmt *stmt = &assert->stmt[i];
		if (stmt->hmac_secret_enc.ptr != NULL) {
			if (aes256_cbc_dec(key, &stmt->hmac_secret_enc,
			    &stmt->hmac_secret) < 0) {
				log_debug("%s: aes256_cbc_dec %zu", __func__, i);
				return (-1);
			}
		}
	}

	return (0);
}

int
fido_dev_get_assert(fido_dev_t *dev, fido_assert_t *assert, const char *pin)
{
	fido_blob_t	*ecdh = NULL;
	es256_pk_t	*pk = NULL;
	int		 r;

	if (assert->rp_id == NULL || assert->cdh.ptr == NULL) {
		log_debug("%s: rp_id=%p, cdh.ptr=%p", __func__,
		    (void *)assert->rp_id, (void *)assert->cdh.ptr);
		return (FIDO_ERR_INVALID_ARGUMENT);
	}

	if (fido_dev_is_fido2(dev) == false) {
		if (pin != NULL || assert->ext != 0)
			return (FIDO_ERR_UNSUPPORTED_OPTION);
		return (u2f_authenticate(dev, assert, -1));
	}

	if (pin != NULL || assert->ext != 0) {
		if ((r = fido_do_ecdh(dev, &pk, &ecdh)) != FIDO_OK) {
			log_debug("%s: fido_do_ecdh", __func__);
			goto fail;
		}
	}
 
	r = fido_dev_get_assert_wait(dev, assert, pk, ecdh, pin, -1);
	if (r == FIDO_OK && assert->ext & FIDO_EXT_HMAC_SECRET)
		if (decrypt_hmac_secrets(assert, ecdh) < 0) {
			log_debug("%s: decrypt_hmac_secrets", __func__);
			r = FIDO_ERR_INTERNAL;
			goto fail;
		}

fail:
	es256_pk_free(&pk);
	fido_blob_free(&ecdh);

	return (r);
}

static int
check_flags(uint8_t flags, bool up, bool uv)
{
	if (up == true && (flags & CTAP_AUTHDATA_USER_PRESENT) == 0) {
		log_debug("%s: CTAP_AUTHDATA_USER_PRESENT", __func__);
		return (-1); /* user not present */
	}

	if (uv == true && (flags & CTAP_AUTHDATA_USER_VERIFIED) == 0) {
		log_debug("%s: CTAP_AUTHDATA_USER_VERIFIED", __func__);
		return (-1); /* user not verified */
	}

	return (0);
}

static int
check_extensions(int authdata_ext, int ext)
{
	if (authdata_ext != ext) {
		log_debug("%s: authdata_ext=0x%x != ext=0x%x", __func__,
		    authdata_ext, ext);
		return (-1);
	}

	return (0);
}

static int
get_signed_hash(fido_blob_t *dgst, const fido_blob_t *clientdata,
    const fido_blob_t *authdata_cbor)
{
	cbor_item_t		*item = NULL;
	unsigned char		*authdata_ptr = NULL;
	size_t			 authdata_len;
	struct cbor_load_result	 cbor;
	SHA256_CTX		 ctx;
	int			 ok = -1;

	if ((item = cbor_load(authdata_cbor->ptr, authdata_cbor->len,
	    &cbor)) == NULL || cbor_isa_bytestring(item) == false ||
	    cbor_bytestring_is_definite(item) == false) {
		log_debug("%s: authdata", __func__);
		goto fail;
	}

	authdata_ptr = cbor_bytestring_handle(item);
	authdata_len = cbor_bytestring_length(item);

	if (dgst->len != SHA256_DIGEST_LENGTH || SHA256_Init(&ctx) == 0 ||
	    SHA256_Update(&ctx, authdata_ptr, authdata_len) == 0 ||
	    SHA256_Update(&ctx, clientdata->ptr, clientdata->len) == 0 ||
	    SHA256_Final(dgst->ptr, &ctx) == 0) {
		log_debug("%s: sha256", __func__);
		goto fail;
	}

	ok = 0;
fail:
	if (item != NULL)
		cbor_decref(&item);

	return (ok);
}

static int
verify_sig_es256(const fido_blob_t *dgst, const es256_pk_t *pk,
    const fido_blob_t *sig)
{
	EVP_PKEY	*pkey = NULL;
	EC_KEY		*ec = NULL;
	int		 ok = -1;

	/* ECDSA_verify needs ints */
	if (dgst->len > INT_MAX || sig->len > INT_MAX) {
		log_debug("%s: dgst->len=%zu, sig->len=%zu", __func__,
		    dgst->len, sig->len);
		return (-1);
	}

	if ((pkey = es256_pk_to_EVP_PKEY(pk)) == NULL ||
	    (ec = EVP_PKEY_get0_EC_KEY(pkey)) == NULL) {
		log_debug("%s: pk -> ec", __func__);
		goto fail;
	}

	if (ECDSA_verify(0, dgst->ptr, (int)dgst->len, sig->ptr,
	    (int)sig->len, ec) != 1) {
		log_debug("%s: ECDSA_verify", __func__);
		goto fail;
	}

	ok = 0;
fail:
	if (pkey != NULL)
		EVP_PKEY_free(pkey);

	return (ok);
}

static int
verify_sig_rs256(const fido_blob_t *dgst, const rs256_pk_t *pk,
    const fido_blob_t *sig)
{
	EVP_PKEY	*pkey = NULL;
	RSA		*rsa = NULL;
	int		 ok = -1;

	/* RSA_verify needs unsigned ints */
	if (dgst->len > UINT_MAX || sig->len > UINT_MAX) {
		log_debug("%s: dgst->len=%zu, sig->len=%zu", __func__,
		    dgst->len, sig->len);
		return (-1);
	}

	if ((pkey = rs256_pk_to_EVP_PKEY(pk)) == NULL ||
	    (rsa = EVP_PKEY_get0_RSA(pkey)) == NULL) {
		log_debug("%s: pk -> ec", __func__);
		goto fail;
	}

	if (RSA_verify(NID_sha256, dgst->ptr, (unsigned int)dgst->len, sig->ptr,
	    (unsigned int)sig->len, rsa) != 1) {
		log_debug("%s: RSA_verify", __func__);
		goto fail;
	}

	ok = 0;
fail:
	if (pkey != NULL)
		EVP_PKEY_free(pkey);

	return (ok);
}

int
fido_assert_verify(const fido_assert_t *assert, size_t idx, int cose_alg,
    const void *pk)
{
	unsigned char		 buf[SHA256_DIGEST_LENGTH];
	fido_blob_t		 dgst;
	const fido_assert_stmt	*stmt = NULL;
	int			 ok = -1;
	int			 r;

	dgst.ptr = buf;
	dgst.len = sizeof(buf);

	if (idx >= assert->stmt_len) {
		r = FIDO_ERR_INVALID_ARGUMENT;
		goto out;
	}

	stmt = &assert->stmt[idx];

	/* do we have everything we need? */
	if (assert->cdh.ptr == NULL || assert->rp_id == NULL ||
	    stmt->authdata_cbor.ptr == NULL || stmt->sig.ptr == NULL) {
		log_debug("%s: cdh=%p, rp_id=%s, authdata=%p, sig=%p", __func__,
		    (void *)assert->cdh.ptr, assert->rp_id,
		    (void *)stmt->authdata_cbor.ptr, (void *)stmt->sig.ptr);
		r = FIDO_ERR_INVALID_ARGUMENT;
		goto out;
	}

	if (check_flags(stmt->authdata.flags, assert->up, assert->uv) < 0) {
		log_debug("%s: check_flags", __func__);
		r = FIDO_ERR_INVALID_PARAM;
		goto out;
	}

	if (check_extensions(stmt->authdata_ext, assert->ext) < 0) {
		log_debug("%s: check_extensions", __func__);
		r = FIDO_ERR_INVALID_PARAM;
		goto out;
	}

	if (check_rp_id(assert->rp_id, stmt->authdata.rp_id_hash) != 0) {
		log_debug("%s: check_rp_id", __func__);
		r = FIDO_ERR_INVALID_PARAM;
		goto out;
	}

	if (get_signed_hash(&dgst, &assert->cdh, &stmt->authdata_cbor) < 0) {
		log_debug("%s: get_signed_hash", __func__);
		r = FIDO_ERR_INTERNAL;
		goto out;
	}

	switch (cose_alg) {
	case COSE_ES256:
		ok = verify_sig_es256(&dgst, pk, &stmt->sig);
		break;
	case COSE_RS256:
		ok = verify_sig_rs256(&dgst, pk, &stmt->sig);
		break;
	default:
		log_debug("%s: unsupported cose_alg %d", __func__, cose_alg);
		r = FIDO_ERR_UNSUPPORTED_OPTION;
		goto out;
	}

	if (ok < 0)
		r = FIDO_ERR_INVALID_SIG;
	else
		r = FIDO_OK;
out:
	explicit_bzero(buf, sizeof(buf));

	return (r);
}

int
fido_assert_set_clientdata_hash(fido_assert_t *assert,
    const unsigned char *hash, size_t hash_len)
{
	if (fido_blob_set(&assert->cdh, hash, hash_len) < 0)
		return (FIDO_ERR_INTERNAL);

	return (FIDO_OK);
}

int
fido_assert_set_hmac_salt(fido_assert_t *assert, const unsigned char *salt,
    size_t salt_len)
{
	if (salt_len != 32 && salt_len != 64)
		return (FIDO_ERR_INVALID_ARGUMENT);

	if (fido_blob_set(&assert->hmac_salt, salt, salt_len) < 0)
		return (FIDO_ERR_INTERNAL);

	return (FIDO_OK);
}

int
fido_assert_set_rp(fido_assert_t *assert, const char *id)
{
	if (assert->rp_id != NULL) {
		free(assert->rp_id);
		assert->rp_id = NULL;
	}

	if ((assert->rp_id = strdup(id)) == NULL)
		return (FIDO_ERR_INTERNAL);

	return (FIDO_OK);
}

int
fido_assert_allow_cred(fido_assert_t *assert, const unsigned char *ptr,
    size_t len)
{
	fido_blob_t	 id;
	fido_blob_t	*list_ptr;
	int		 r;

	memset(&id, 0, sizeof(id));

	if (assert->allow_list.len == SIZE_MAX) {
		r = FIDO_ERR_INVALID_ARGUMENT;
		goto fail;
	}

	if (fido_blob_set(&id, ptr, len) < 0 || (list_ptr =
	    recallocarray(assert->allow_list.ptr, assert->allow_list.len,
	    assert->allow_list.len + 1, sizeof(fido_blob_t))) == NULL) {
		r = FIDO_ERR_INTERNAL;
		goto fail;
	}

	list_ptr[assert->allow_list.len++] = id;
	assert->allow_list.ptr = list_ptr;

	return (FIDO_OK);
fail:
	free(id.ptr);

	return (r);

}

int
fido_assert_set_extensions(fido_assert_t *assert, int ext)
{
	if (ext != 0 && ext != FIDO_EXT_HMAC_SECRET)
		return (FIDO_ERR_INVALID_ARGUMENT);

	assert->ext = ext;

	return (FIDO_OK);
}

int
fido_assert_set_options(fido_assert_t *assert, bool up, bool uv)
{
	assert->up = up;
	assert->uv = uv;

	return (FIDO_OK);
}

const unsigned char *
fido_assert_clientdata_hash_ptr(const fido_assert_t *assert)
{
	return (assert->cdh.ptr);
}

size_t
fido_assert_clientdata_hash_len(const fido_assert_t *assert)
{
	return (assert->cdh.len);
}

fido_assert_t *
fido_assert_new(void)
{
	return (calloc(1, sizeof(fido_assert_t)));
}

void
fido_assert_reset_tx(fido_assert_t *assert)
{
	free(assert->rp_id);
	free(assert->cdh.ptr);
	free(assert->hmac_salt.ptr);
	free_blob_array(&assert->allow_list);

	memset(&assert->cdh, 0, sizeof(assert->cdh));
	memset(&assert->hmac_salt, 0, sizeof(assert->hmac_salt));
	memset(&assert->allow_list, 0, sizeof(assert->allow_list));

	assert->rp_id = NULL;
	assert->up = false;
	assert->uv = false;
	assert->ext = 0;
}

void
fido_assert_reset_rx(fido_assert_t *assert)
{
	for (size_t i = 0; i < assert->stmt_cnt; i++) {
		free(assert->stmt[i].user.id.ptr);
		free(assert->stmt[i].user.icon);
		free(assert->stmt[i].user.name);
		free(assert->stmt[i].user.display_name);
		free(assert->stmt[i].id.ptr);
		if (assert->stmt[i].hmac_secret.ptr != NULL) {
			explicit_bzero(assert->stmt[i].hmac_secret.ptr,
			    assert->stmt[i].hmac_secret.len);
		}
		free(assert->stmt[i].hmac_secret.ptr);
		free(assert->stmt[i].hmac_secret_enc.ptr);
		free(assert->stmt[i].authdata_cbor.ptr);
		free(assert->stmt[i].sig.ptr);
		memset(&assert->stmt[i], 0, sizeof(assert->stmt[i]));
	}

	free(assert->stmt);

	assert->stmt = NULL;
	assert->stmt_len = 0;
	assert->stmt_cnt = 0;
}

void
fido_assert_free(fido_assert_t **assert_p)
{
	fido_assert_t *assert;

	if (assert_p == NULL || (assert = *assert_p) == NULL)
		return;

	fido_assert_reset_tx(assert);
	fido_assert_reset_rx(assert);

	free(assert);

	*assert_p = NULL;
}

size_t
fido_assert_count(const fido_assert_t *assert)
{
	return (assert->stmt_len);
}

const char *
fido_assert_rp_id(const fido_assert_t *assert)
{
	return (assert->rp_id);
}

uint8_t
fido_assert_flags(const fido_assert_t *assert, size_t idx)
{
	if (idx >= assert->stmt_len)
		return (0);

	return (assert->stmt[idx].authdata.flags);
}

const unsigned char *
fido_assert_authdata_ptr(const fido_assert_t *assert, size_t idx)
{
	if (idx >= assert->stmt_len)
		return (NULL);

	return (assert->stmt[idx].authdata_cbor.ptr);
}

size_t
fido_assert_authdata_len(const fido_assert_t *assert, size_t idx)
{
	if (idx >= assert->stmt_len)
		return (0);

	return (assert->stmt[idx].authdata_cbor.len);
}

const unsigned char *
fido_assert_sig_ptr(const fido_assert_t *assert, size_t idx)
{
	if (idx >= assert->stmt_len)
		return (NULL);

	return (assert->stmt[idx].sig.ptr);
}

size_t
fido_assert_sig_len(const fido_assert_t *assert, size_t idx)
{
	if (idx >= assert->stmt_len)
		return (0);

	return (assert->stmt[idx].sig.len);
}

const unsigned char *
fido_assert_id_ptr(const fido_assert_t *assert, size_t idx)
{
	if (idx >= assert->stmt_len)
		return (NULL);

	return (assert->stmt[idx].id.ptr);
}

size_t
fido_assert_id_len(const fido_assert_t *assert, size_t idx)
{
	if (idx >= assert->stmt_len)
		return (0);

	return (assert->stmt[idx].id.len);
}

const unsigned char *
fido_assert_user_id_ptr(const fido_assert_t *assert, size_t idx)
{
	if (idx >= assert->stmt_len)
		return (NULL);

	return (assert->stmt[idx].user.id.ptr);
}

size_t
fido_assert_user_id_len(const fido_assert_t *assert, size_t idx)
{
	if (idx >= assert->stmt_len)
		return (0);

	return (assert->stmt[idx].user.id.len);
}

const char *
fido_assert_user_icon(const fido_assert_t *assert, size_t idx)
{
	if (idx >= assert->stmt_len)
		return (NULL);

	return (assert->stmt[idx].user.icon);
}

const char *
fido_assert_user_name(const fido_assert_t *assert, size_t idx)
{
	if (idx >= assert->stmt_len)
		return (NULL);

	return (assert->stmt[idx].user.name);
}

const char *
fido_assert_user_display_name(const fido_assert_t *assert, size_t idx)
{
	if (idx >= assert->stmt_len)
		return (NULL);

	return (assert->stmt[idx].user.display_name);
}

const unsigned char *
fido_assert_hmac_secret_ptr(const fido_assert_t *assert, size_t idx)
{
	if (idx >= assert->stmt_len)
		return (NULL);

	return (assert->stmt[idx].hmac_secret.ptr);
}

size_t
fido_assert_hmac_secret_len(const fido_assert_t *assert, size_t idx)
{
	if (idx >= assert->stmt_len)
		return (0);

	return (assert->stmt[idx].hmac_secret.len);
}

static void
fido_assert_clean_authdata(fido_assert_stmt *as)
{
	free(as->authdata_cbor.ptr);

	memset(&as->authdata_ext, 0, sizeof(as->authdata_ext));
	memset(&as->authdata_cbor, 0, sizeof(as->authdata_cbor));
	memset(&as->authdata, 0, sizeof(as->authdata));
}

int
fido_assert_set_authdata(fido_assert_t *assert, size_t idx,
    const unsigned char *ptr, size_t len)
{
	cbor_item_t		*item = NULL;
	fido_assert_stmt	*stmt = NULL;
	struct cbor_load_result	 cbor;
	int			 r;

	if (idx >= assert->stmt_len)
		return (FIDO_ERR_INVALID_ARGUMENT);

	stmt = &assert->stmt[idx];
	fido_assert_clean_authdata(stmt);

	if ((item = cbor_load(ptr, len, &cbor)) == NULL) {
		log_debug("%s: cbor_load", __func__);
		r = FIDO_ERR_INVALID_ARGUMENT;
		goto fail;
	}

	if (decode_assert_authdata(item, &stmt->authdata_cbor, &stmt->authdata,
	    &stmt->authdata_ext, &stmt->hmac_secret_enc) < 0) {
		log_debug("%s: decode_assert_authdata", __func__);
		r = FIDO_ERR_INVALID_ARGUMENT;
		goto fail;
	}

	r = FIDO_OK;
fail:
	if (item != NULL)
		cbor_decref(&item);

	if (r != FIDO_OK)
		fido_assert_clean_authdata(stmt);

	return (r);
}

static void
fido_assert_clean_sig(fido_assert_stmt *as)
{
	free(as->sig.ptr);
	as->sig.ptr = NULL;
	as->sig.len = 0;
}

int
fido_assert_set_sig(fido_assert_t *a, size_t idx, const unsigned char *ptr,
    size_t len)
{
	unsigned char *sig;

	if (idx >= a->stmt_len)
		return (FIDO_ERR_INVALID_ARGUMENT);

	fido_assert_clean_sig(&a->stmt[idx]);

	if ((sig = malloc(len)) == NULL)
		return (FIDO_ERR_INTERNAL);

	memcpy(sig, ptr, len);
	a->stmt[idx].sig.ptr = sig;
	a->stmt[idx].sig.len = len;

	return (FIDO_OK);
}

/* XXX shrinking leaks memory; fortunately that shouldn't happen */
int
fido_assert_set_count(fido_assert_t *assert, size_t n)
{
	void *new_stmt;

	new_stmt = recallocarray(assert->stmt, assert->stmt_cnt, n,
	    sizeof(fido_assert_stmt));
	if (new_stmt == NULL)
		return (FIDO_ERR_INTERNAL);

	assert->stmt = new_stmt;
	assert->stmt_cnt = n;
	assert->stmt_len = n;

	return (FIDO_OK);
}
