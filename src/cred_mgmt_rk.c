/*
 * Copyright (c) 2019 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <openssl/sha.h>

#include <string.h>

#include "fido.h"
#include "fido/es256.h"

#define ENUM_RK_BEGIN	0x04
#define ENUM_RK_NEXT	0x05

static int
parse_cred_mgmt_rk(const cbor_item_t *key, const cbor_item_t *val, void *arg)
{
	fido_cred_t *cred = arg;

	if (cbor_isa_uint(key) == false ||
	    cbor_int_get_width(key) != CBOR_INT_8) {
		log_debug("%s: cbor type", __func__);
		return (0); /* ignore */
	}

	switch (cbor_get_uint8(key)) {
	case 6: /* user entity */
		return (decode_user(val, &cred->user));
	case 7:
		return (decode_cred_id(val, &cred->attcred.id));
	case 8:
		return (decode_pubkey(val, &cred->attcred.type,
		    &cred->attcred.pubkey));
	default: /* ignore */
		log_debug("%s: cbor type", __func__);
		return (0);
	}
}

static int
rk_set_count(fido_cred_mgmt_rk_t *rk, size_t n)
{
	void *new_ptr;

#ifdef FIDO_FUZZ
	if (n > UINT8_MAX) {
		log_debug("%s: n > UINT8_MAX", __func__);
		return (-1);
	}
#endif

	if (n < rk->n_alloc)
		return (0);

	if (rk->n_rx > 0 || rk->n_rx > rk->n_alloc || n < rk->n_alloc) {
		log_debug("%s: n=%zu, n_rx=%zu, n_alloc=%zu", __func__, n,
		    rk->n_rx, rk->n_alloc);
		return (-1);
	}

	new_ptr = recallocarray(rk->ptr, rk->n_alloc, n, sizeof(*rk->ptr));
	if (new_ptr == NULL)
		return (-1);

	rk->ptr = new_ptr;
	rk->n_alloc = n;

	return (0);
}

static void
rk_reset(fido_cred_mgmt_rk_t *rk)
{
	for (size_t i = 0; i < rk->n_alloc; i++) {
		fido_cred_reset_tx(&rk->ptr[i]);
		fido_cred_reset_rx(&rk->ptr[i]);
	}

	free(rk->ptr);
	rk->ptr = NULL;

	memset(rk, 0, sizeof(*rk));
}

static int
parse_cred_mgmt_rk_count(const cbor_item_t *key, const cbor_item_t *val,
    void *arg)
{
	fido_cred_mgmt_rk_t	*rk = arg;
	uint64_t		 n;

	/* totalCredentials */
	if (cbor_isa_uint(key) == false ||
	    cbor_int_get_width(key) != CBOR_INT_8 ||
	    cbor_get_uint8(key) != 9) {
		log_debug("%s: cbor_type", __func__);
		return (0); /* ignore */
	}

	if (decode_uint64(val, &n) < 0 || n > SIZE_MAX) {
		log_debug("%s: decode_uint64", __func__);
		return (-1);
	}

	if (rk_set_count(rk, n) < 0) {
		log_debug("%s: rk_set_count", __func__);
		return (-1);
	}

	return (0);
}

static int
cred_mgmt_rk_tx(fido_dev_t *dev, const char *rp_id, const char *pin)
{
	fido_blob_t	 f;
	fido_blob_t	*ecdh = NULL;
	fido_blob_t	 hmac;
	fido_blob_t	 rp_dgst;
	uint8_t		 dgst[SHA256_DIGEST_LENGTH];
	es256_pk_t	*pk = NULL;
	cbor_item_t	*argv[4];
	cbor_item_t	*rp_cbor[1];
	int		 r = FIDO_ERR_INTERNAL;

	memset(&f, 0, sizeof(f));
	memset(&hmac, 0, sizeof(hmac));
	memset(argv, 0, sizeof(argv));
	memset(rp_cbor, 0, sizeof(rp_cbor));

	rp_dgst.ptr = dgst;
	rp_dgst.len = sizeof(dgst);

	if (SHA256((const unsigned char *)rp_id, strlen(rp_id), dgst) != dgst) {
		log_debug("%s: sha256", __func__);
		goto fail;
	}

	/* subCommand + subCommandParams */
	if ((argv[0] = cbor_build_uint8(ENUM_RK_BEGIN)) == NULL ||
	    (rp_cbor[0] = fido_blob_encode(&rp_dgst)) == NULL ||
	    (argv[1] = cbor_flatten_vector(rp_cbor, 1)) == NULL) {
		log_debug("%s: cbor encode", __func__);
		goto fail;
	}

	if (cbor_build_frame(ENUM_RK_BEGIN, &rp_cbor[0], 1, &hmac) < 0) {
		log_debug("%s: cbor_build_frame", __func__);
		goto fail;
	}

	if ((r = fido_do_ecdh(dev, &pk, &ecdh)) != FIDO_OK) {
		log_debug("%s: fido_do_ecdh", __func__);
		goto fail;
	}

	/* pinProtocol, pinAuth */
	if ((r = add_cbor_pin_params(dev, &hmac, pk, ecdh, pin, &argv[3],
	    &argv[2])) != FIDO_OK) {
		log_debug("%s: add_cbor_pin_params", __func__);
		goto fail;
	}

	/* framing and transmission */
	if (cbor_build_frame(CTAP_CBOR_CRED_MGMT_PRE, argv, 4, &f) < 0 ||
	    tx(dev, CTAP_FRAME_INIT | CTAP_CMD_CBOR, f.ptr, f.len) < 0) {
		log_debug("%s: tx", __func__);
		r = FIDO_ERR_TX;
		goto fail;
	}

	r = FIDO_OK;
fail:
	es256_pk_free(&pk);
	fido_blob_free(&ecdh);

	for (size_t i = 0; i < 4; i++)
		if (argv[i])
			cbor_decref(&argv[i]);

	if (rp_cbor[0])
		cbor_decref(&rp_cbor[0]);

	free(f.ptr);
	free(hmac.ptr);

	return (r);
}

static int
cred_mgmt_rk_rx(fido_dev_t *dev, fido_cred_mgmt_rk_t *rk, int ms)
{
	const uint8_t	cmd = CTAP_FRAME_INIT | CTAP_CMD_CBOR;
	unsigned char	reply[2048];
	int		reply_len;
	int		r;

	rk_reset(rk);

	if ((reply_len = rx(dev, cmd, &reply, sizeof(reply), ms)) < 0) {
		log_debug("%s: rx", __func__);
		return (FIDO_ERR_RX);
	}

	/* adjust as needed */
	if ((r = parse_cbor_reply(reply, (size_t)reply_len, rk,
	    parse_cred_mgmt_rk_count)) != FIDO_OK) {
		log_debug("%s: parse_cred_mgmt_rk_count", __func__);
		return (r);
	}

	if (rk->n_alloc == 0) {
		log_debug("%s: n_alloc=0", __func__);
		return (FIDO_OK);
	}

	/* parse the first rk */
	if ((r = parse_cbor_reply(reply, (size_t)reply_len, &rk->ptr[0],
	    parse_cred_mgmt_rk)) != FIDO_OK) {
		log_debug("%s: parse_cred_mgmt_rk", __func__);
		return (r);
	}

	rk->n_rx++;

	return (FIDO_OK);
}

static int
cred_mgmt_next_rk_rx(fido_dev_t *dev, fido_cred_mgmt_rk_t *rk, int ms)
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
	if (rk->n_rx >= rk->n_alloc) {
		log_debug("%s: n_rx=%zu, n_alloc=%zu", __func__, rk->n_rx,
		    rk->n_alloc);
		return (FIDO_ERR_INTERNAL);
	}

	if ((r = parse_cbor_reply(reply, (size_t)reply_len, &rk->ptr[rk->n_rx],
	    parse_cred_mgmt_rk)) != FIDO_OK) {
		log_debug("%s: parse_cred_mgmt_rk", __func__);
		return (r);
	}

	return (FIDO_OK);
}

static int
cred_mgmt_rk_wait(fido_dev_t *dev, const char *rp_id, fido_cred_mgmt_rk_t *rk,
    const char *pin, int ms)
{
	int r;

	if ((r = cred_mgmt_rk_tx(dev, rp_id, pin)) != FIDO_OK ||
	    (r = cred_mgmt_rk_rx(dev, rk, ms)) != FIDO_OK)
		return (r);

	while (rk->n_rx < rk->n_alloc) {
		if ((r = cred_mgmt_tx_common(dev, ENUM_RK_NEXT,
		    NULL)) != FIDO_OK || (r = cred_mgmt_next_rk_rx(dev, rk,
		    ms)) != FIDO_OK)
			return (r);
		rk->n_rx++;
	}

	return (FIDO_OK);
}

int
fido_dev_get_cred_mgmt_rk(fido_dev_t *dev, const char *rp_id,
    fido_cred_mgmt_rk_t *rk, const char *pin)
{
	if (fido_dev_is_fido2(dev) == false)
		return (FIDO_ERR_INVALID_COMMAND);
	if (pin == NULL)
		return (FIDO_ERR_INVALID_ARGUMENT);

	return (cred_mgmt_rk_wait(dev, rp_id, rk, pin, -1));
}

fido_cred_mgmt_rk_t *
fido_cred_mgmt_rk_new(void)
{
	return (calloc(1, sizeof(fido_cred_mgmt_rk_t)));
}

void
fido_cred_mgmt_rk_free(fido_cred_mgmt_rk_t **rk_p)
{
	fido_cred_mgmt_rk_t *rk;

	if (rk_p == NULL || (rk = *rk_p) == NULL)
		return;

	rk_reset(rk);
	free(rk);
	*rk_p = NULL;
}

size_t
fido_cred_mgmt_rk_count(const fido_cred_mgmt_rk_t *rk)
{
	return (rk->n_rx);
}

const fido_cred_t *
fido_cred_mgmt_rk(const fido_cred_mgmt_rk_t *rk, size_t idx)
{
	if (idx >= rk->n_alloc)
		return (NULL);

	return (&rk->ptr[idx]);
}
