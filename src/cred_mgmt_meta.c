/*
 * Copyright (c) 2019 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <string.h>

#include "fido.h"
#include "fido/es256.h"

#define GET_CRED_METADATA	0x01

static int
parse_cred_mgmt_metadata(const cbor_item_t *key, const cbor_item_t *val,
    void *arg)
{
	fido_cred_mgmt_metadata_t *metadata = arg;

	if (cbor_isa_uint(key) == false ||
	    cbor_int_get_width(key) != CBOR_INT_8) {
		log_debug("%s: cbor type", __func__);
		return (0); /* ignore */
	}

	switch (cbor_get_uint8(key)) {
	case 1:
		return (decode_uint64(val, &metadata->rk_existing));
	case 2:
		return (decode_uint64(val, &metadata->rk_remaining));
	default:
		log_debug("%s: cbor type", __func__);
		return (0); /* ignore */
	}
}

static int
get_cred_mgmt_metadata_rx(fido_dev_t *dev, fido_cred_mgmt_metadata_t *metadata,
    int ms)
{
	const uint8_t	cmd = CTAP_FRAME_INIT | CTAP_CMD_CBOR;
	unsigned char	reply[512];
	int		reply_len;
	int		r;

	memset(metadata, 0, sizeof(*metadata));

	if ((reply_len = rx(dev, cmd, &reply, sizeof(reply), ms)) < 0) {
		log_debug("%s: rx", __func__);
		return (FIDO_ERR_RX);
	}

	if ((r = parse_cbor_reply(reply, (size_t)reply_len, metadata,
	    parse_cred_mgmt_metadata)) != FIDO_OK) {
		log_debug("%s: parse_cred_mgmt_metadata", __func__);
		return (r);
	}

	return (FIDO_OK);
}

static int
get_cred_mgmt_metadata_tx(fido_dev_t *dev, const char *pin)
{
	fido_blob_t	 f;
	fido_blob_t	*ecdh = NULL;
	fido_blob_t	 hmac;
	es256_pk_t	*pk = NULL;
	cbor_item_t	*argv[4];
	uint8_t		 subcmd = GET_CRED_METADATA;
	int		 r;

	memset(&f, 0, sizeof(f));
	memset(&argv, 0, sizeof(argv));

	hmac.ptr = &subcmd;
	hmac.len = sizeof(subcmd);

	if (pin == NULL) {
		log_debug("%s: NULL pin", __func__);
		r = FIDO_ERR_INVALID_ARGUMENT;
		goto fail;
	}

	if ((r = fido_do_ecdh(dev, &pk, &ecdh)) != FIDO_OK) {
		log_debug("%s: fido_do_ecdh", __func__);
		goto fail;
	}

	/* subCommand */
	if ((argv[0] = cbor_build_uint8(subcmd)) == NULL) {
		log_debug("%s: cbor encode", __func__);
		r = FIDO_ERR_INTERNAL;
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

	free(f.ptr);

	return (r);
}

static int
get_cred_mgmt_metadata_wait(fido_dev_t *dev,
    fido_cred_mgmt_metadata_t *metadata, const  char *pin, int ms)
{
	int r;

	if ((r = get_cred_mgmt_metadata_tx(dev, pin)) != FIDO_OK ||
	    (r = get_cred_mgmt_metadata_rx(dev, metadata, ms)) != FIDO_OK)
		return (r);

	return (FIDO_OK);
}

int
fido_dev_get_cred_mgmt_metadata(fido_dev_t *dev,
    fido_cred_mgmt_metadata_t *metadata, const char *pin)
{
	if (fido_dev_is_fido2(dev) == false)
		return (FIDO_ERR_INVALID_COMMAND);

	return (get_cred_mgmt_metadata_wait(dev, metadata, pin, -1));
}

fido_cred_mgmt_metadata_t *
fido_cred_mgmt_metadata_new(void)
{
	return (calloc(1, sizeof(fido_cred_mgmt_metadata_t)));
}

void
fido_cred_mgmt_metadata_free(fido_cred_mgmt_metadata_t **metadata_p)
{
	fido_cred_mgmt_metadata_t *metadata;

	if (metadata_p == NULL || (metadata = *metadata_p) == NULL)
		return;

	free(metadata);

	*metadata_p = NULL;
}

uint64_t
fido_cred_mgmt_rk_existing(const fido_cred_mgmt_metadata_t *metadata)
{
	return (metadata->rk_existing);
}

uint64_t
fido_cred_mgmt_rk_remaining(const fido_cred_mgmt_metadata_t *metadata)
{
	return (metadata->rk_remaining);
}
