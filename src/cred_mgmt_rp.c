/*
 * Copyright (c) 2019 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <string.h>

#include "fido.h"
#include "fido/es256.h"

#define ENUM_RP_BEGIN	0x02
#define ENUM_RP_NEXT	0x03

static int
parse_cred_mgmt_rp(const cbor_item_t *key, const cbor_item_t *val, void *arg)
{
	fido_cred_mgmt_rp_info_t *rp_info = arg;

	if (cbor_isa_uint(key) == false ||
	    cbor_int_get_width(key) != CBOR_INT_8) {
		log_debug("%s: cbor type", __func__);
		return (0); /* ignore */
	}

	switch (cbor_get_uint8(key)) {
	case 3: /* rp entity */
		return (decode_rp_entity(val, &rp_info->rp));
	case 4: /* rp id hash */
		return (fido_blob_decode(val, &rp_info->rp_id_hash));
	default: /* ignore */
		log_debug("%s: cbor type", __func__);
		return (0);
	}
}

static int
rp_set_count(fido_cred_mgmt_rp_t *rp, size_t n)
{
	void *new_ptr;

#ifdef FIDO_FUZZ
	if (n > UINT8_MAX) {
		log_debug("%s: n > UINT8_MAX", __func__);
		return (-1);
	}
#endif

	if (n < rp->n_alloc)
		return (0);

	if (rp->n_rx > 0 || rp->n_rx > rp->n_alloc || n < rp->n_alloc) {
		log_debug("%s: n=%zu, n_rx=%zu, n_alloc=%zu", __func__, n,
		    rp->n_rx, rp->n_alloc);
		return (-1);
	}

	new_ptr = recallocarray(rp->ptr, rp->n_alloc, n, sizeof(*rp->ptr));
	if (new_ptr == NULL)
		return (-1);

	rp->ptr = new_ptr;
	rp->n_alloc = n;

	return (0);
}

static void
rp_reset(fido_cred_mgmt_rp_t *rp)
{
	for (size_t i = 0; i < rp->n_alloc; i++) {
		free(rp->ptr[i].rp.id);
		free(rp->ptr[i].rp.name);
		rp->ptr[i].rp.id = NULL;
		rp->ptr[i].rp.name = NULL;
		free(rp->ptr[i].rp_id_hash.ptr);
		memset(&rp->ptr[i].rp_id_hash, 0,
		    sizeof(rp->ptr[i].rp_id_hash));
	}

	free(rp->ptr);
	rp->ptr = NULL;

	memset(rp, 0, sizeof(*rp));
}

static int
parse_cred_mgmt_rp_count(const cbor_item_t *key, const cbor_item_t *val,
    void *arg)
{
	fido_cred_mgmt_rp_t	*rp = arg;
	uint64_t		 n;

	/* totalRPs */
	if (cbor_isa_uint(key) == false ||
	    cbor_int_get_width(key) != CBOR_INT_8 ||
	    cbor_get_uint8(key) != 5) {
		log_debug("%s: cbor_type", __func__);
		return (0); /* ignore */
	}

	if (decode_uint64(val, &n) < 0 || n > SIZE_MAX) {
		log_debug("%s: decode_uint64", __func__);
		return (-1);
	}

	if (rp_set_count(rp, n) < 0) {
		log_debug("%s: rp_set_count", __func__);
		return (-1);
	}

	return (0);
}

static int
cred_mgmt_rp_rx(fido_dev_t *dev, fido_cred_mgmt_rp_t *rp, int ms)
{
	const uint8_t	cmd = CTAP_FRAME_INIT | CTAP_CMD_CBOR;
	unsigned char	reply[2048];
	int		reply_len;
	int		r;

	rp_reset(rp);

	if ((reply_len = rx(dev, cmd, &reply, sizeof(reply), ms)) < 0) {
		log_debug("%s: rx", __func__);
		return (FIDO_ERR_RX);
	}

	/* adjust as needed */
	if ((r = parse_cbor_reply(reply, (size_t)reply_len, rp,
	    parse_cred_mgmt_rp_count)) != FIDO_OK) {
		log_debug("%s: parse_cred_mgmt_rp_count", __func__);
		return (r);
	}

	if (rp->n_alloc == 0) {
		log_debug("%s: n_alloc=0", __func__);
		return (FIDO_OK);
	}

	/* parse the first rp */
	if ((r = parse_cbor_reply(reply, (size_t)reply_len, &rp->ptr[0],
	    parse_cred_mgmt_rp)) != FIDO_OK) {
		log_debug("%s: parse_cred_mgmt_rp", __func__);
		return (r);
	}

	rp->n_rx++;

	return (FIDO_OK);
}

static int
cred_mgmt_next_rp_rx(fido_dev_t *dev, fido_cred_mgmt_rp_t *rp, int ms)
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
	if (rp->n_rx >= rp->n_alloc) {
		log_debug("%s: n_rx=%zu, n_alloc=%zu", __func__, rp->n_rx,
		    rp->n_alloc);
		return (FIDO_ERR_INTERNAL);
	}

	if ((r = parse_cbor_reply(reply, (size_t)reply_len, &rp->ptr[rp->n_rx],
	    parse_cred_mgmt_rp)) != FIDO_OK) {
		log_debug("%s: parse_cred_mgmt_rp", __func__);
		return (r);
	}

	return (FIDO_OK);
}

static int
cred_mgmt_rp_wait(fido_dev_t *dev, fido_cred_mgmt_rp_t *rp, const char *pin,
    int ms)
{
	int r;

	if ((r = cred_mgmt_tx_common(dev, ENUM_RP_BEGIN, pin)) != FIDO_OK ||
	    (r = cred_mgmt_rp_rx(dev, rp, ms)) != FIDO_OK)
		return (r);

	while (rp->n_rx < rp->n_alloc) {
		if ((r = cred_mgmt_tx_common(dev, ENUM_RP_NEXT,
		    NULL)) != FIDO_OK || (r = cred_mgmt_next_rp_rx(dev, rp,
		    ms)) != FIDO_OK)
			return (r);
		rp->n_rx++;
	}

	return (FIDO_OK);
}

int
fido_dev_get_cred_mgmt_rp(fido_dev_t *dev, fido_cred_mgmt_rp_t *rp,
    const char *pin)
{
	if (fido_dev_is_fido2(dev) == false)
		return (FIDO_ERR_INVALID_COMMAND);
	if (pin == NULL)
		return (FIDO_ERR_INVALID_ARGUMENT);

	return (cred_mgmt_rp_wait(dev, rp, pin, -1));
}

fido_cred_mgmt_rp_t *
fido_cred_mgmt_rp_new(void)
{
	return (calloc(1, sizeof(fido_cred_mgmt_rp_t)));
}

void
fido_cred_mgmt_rp_free(fido_cred_mgmt_rp_t **rp_p)
{
	fido_cred_mgmt_rp_t *rp;

	if (rp_p == NULL || (rp = *rp_p) == NULL)
		return;

	rp_reset(rp);
	free(rp);
	*rp_p = NULL;
}

size_t
fido_cred_mgmt_rp_count(const fido_cred_mgmt_rp_t *rp)
{
	return (rp->n_rx);
}

const char *
fido_cred_mgmt_rp_id(const fido_cred_mgmt_rp_t *rp, size_t idx)
{
	if (idx >= rp->n_alloc)
		return (NULL);

	return (rp->ptr[idx].rp.id);
}

const char *
fido_cred_mgmt_rp_name(const fido_cred_mgmt_rp_t *rp, size_t idx)
{
	if (idx >= rp->n_alloc)
		return (NULL);

	return (rp->ptr[idx].rp.name);
}

size_t
fido_cred_mgmt_rp_id_hash_len(const fido_cred_mgmt_rp_t *rp, size_t idx)
{
	if (idx >= rp->n_alloc)
		return (0);

	return (rp->ptr[idx].rp_id_hash.len);
}

const unsigned char *
fido_cred_mgmt_rp_id_hash_ptr(const fido_cred_mgmt_rp_t *rp, size_t idx)
{
	if (idx >= rp->n_alloc)
		return (NULL);

	return (rp->ptr[idx].rp_id_hash.ptr);
}
