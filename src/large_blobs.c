/*
 * Copyright (c) 2020 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <openssl/sha.h>

#include "fido.h"
#include "fido/credman.h"
#include "fido/es256.h"

#define LARGE_BLOBS_DIGEST_LENGTH (16)
#define LARGE_BLOBS_IV_LENGTH     (12)
#define LARGE_BLOBS_TAG_LENGTH    (16)

typedef struct large_blob {
	fido_blob_t ct;
	fido_blob_t iv;
	size_t      sz;
} large_blob_t;

static large_blob_t *
large_blob_new(void)
{
	return (calloc(1, sizeof(large_blob_t)));
}

static int
large_blob_gen_iv(large_blob_t *blob)
{
	uint8_t	  buf[LARGE_BLOBS_IV_LENGTH];
	int	  r = -1;

	if (fido_get_random(buf, sizeof(buf)) < 0 ||
	    fido_blob_set(&blob->iv, buf, sizeof(buf)) < 0)
		goto fail;

	r = 0;

fail:
	explicit_bzero(buf, sizeof(buf));

	return (r);
}

static void
large_blob_reset(large_blob_t *blob)
{
	fido_blob_reset(&blob->ct);
	fido_blob_reset(&blob->iv);
	blob->sz = 0;
}

static void
large_blob_free(large_blob_t **blob_p)
{
	large_blob_t	*blob;

	if (blob_p == NULL || *blob_p == NULL)
		return;

	blob = *blob_p;
	large_blob_reset(blob);
	free(blob);

	blob_p = NULL;
}

static fido_blob_t *
large_blob_ad(uint64_t size)
{
	uint8_t		 buf[4 + sizeof(uint64_t)];
	fido_blob_t	*ad = NULL;

	buf[0] = 0x62; /* b */
	buf[1] = 0x6c; /* l */
	buf[2] = 0x6f; /* o */
	buf[3] = 0x62; /* b */
	size = htole64(size);
	memcpy(&buf[4], &size, sizeof(uint64_t));

	if ((ad = fido_blob_new()) == NULL ||
	    fido_blob_set(ad, buf, sizeof(buf)) < 0)
		fido_blob_free(&ad);

	return (ad);
}

static fido_blob_t *
large_blob_pt(const large_blob_t *blob, const fido_blob_t *key)
{
	fido_blob_t	*ad = NULL;
	fido_blob_t	*pt = NULL;

	if ((pt = fido_blob_new()) == NULL ||
	    (ad = large_blob_ad(blob->sz)) == NULL ||
	    aes256_gcm_dec(key, &blob->iv, ad, &blob->ct, pt) < 0)
		fido_blob_free(&pt);

	fido_blob_free(&ad);

	return (pt);
}

static int
large_blob_comp_enc(large_blob_t *blob, const fido_blob_t *pt,
    const fido_blob_t *key)
{
	fido_blob_t	*ad = NULL;
	fido_blob_t	*df = NULL;
	int		 ok = -1;

	if ((df = fido_blob_new()) == NULL ||
	    (ad = large_blob_ad(pt->len)) == NULL ||
	    large_blob_gen_iv(blob) < 0 ||
	    fido_compress(df, pt) != FIDO_OK ||
	    aes256_gcm_enc(key, &blob->iv, ad, df, &blob->ct) < 0)
		goto fail;

	blob->sz = pt->len;

	ok = 0;
fail:
	fido_blob_free(&df);
	fido_blob_free(&ad);

	return (ok);
}

static int
prepare_hmac(const size_t offset, const unsigned char *data, const size_t len,
    fido_blob_t *hmac)
{
	uint32_t	tmp;
	uint8_t		buf[32 + 2 + sizeof(uint32_t) + SHA256_DIGEST_LENGTH];
	const size_t	dgst_pos = sizeof(buf) - SHA256_DIGEST_LENGTH;

	memset(buf, 0xff, 32);
	buf[32] = CTAP_CBOR_LARGE_BLOBS;
	buf[33] = 0x00;

	if (offset > UINT32_MAX) {
		fido_log_debug("%s: offset=%zu", __func__, offset);
		return (-1);
	}

	tmp = htole32((uint32_t)offset);
	memcpy(&buf[34], &tmp, sizeof(uint32_t));

	if (data == NULL || len == 0 ||
	    SHA256(data, len, &buf[dgst_pos]) != &buf[dgst_pos]) {
		fido_log_debug("%s: sha256", __func__);
		return (-1);
	}

	return (fido_blob_set(hmac, buf, sizeof(buf)));
}

static size_t
max_fragment_length(fido_dev_t *dev)
{
	uint64_t	maxfraglen;

	maxfraglen = fido_dev_maxmsgsize(dev);
	if (maxfraglen > SIZE_MAX)
		maxfraglen = SIZE_MAX;
	if (maxfraglen > FIDO_MAXMSG)
		maxfraglen = FIDO_MAXMSG;

	maxfraglen = maxfraglen > 64 ? maxfraglen - 64 : 0;

	return ((size_t)maxfraglen);
}

static int
parse_large_blob_reply(const cbor_item_t *key, const cbor_item_t *val, void *arg)
{
	fido_blob_t	*fragment = arg;

	if (cbor_isa_uint(key) == false ||
	    cbor_int_get_width(key) != CBOR_INT_8) {
		fido_log_debug("%s: cbor type", __func__);
		return (0); /* ignore */
	}

	switch (cbor_get_uint8(key)) {
	case 1: /* substring of serialized large blob array */
		return (fido_blob_decode(val, fragment));
	default: /* ignore */
		fido_log_debug("%s: cbor type", __func__);
		return (0);
	}
}

static int
large_blob_array_digest(const unsigned char *data, const size_t len,
    unsigned char dgst[LARGE_BLOBS_DIGEST_LENGTH])
{
	unsigned char	actual_dgst[SHA256_DIGEST_LENGTH];

	explicit_bzero(actual_dgst, sizeof(actual_dgst));
	if (data == NULL || len == 0 ||
	    SHA256(data, len, actual_dgst) != actual_dgst) {
		fido_log_debug("%s: sha256", __func__);
		return (-1);
	}

	memcpy(dgst, actual_dgst, LARGE_BLOBS_DIGEST_LENGTH);
	return (0);
}

static int
validate_large_blob_array(const fido_blob_t *b)
{
	unsigned char	dgst[LARGE_BLOBS_DIGEST_LENGTH];
	size_t		offset;

	if (b->len <= sizeof(dgst))
		return (-1);

	offset = b->len - sizeof(dgst);

	if (large_blob_array_digest(b->ptr, offset, dgst))
		return (-1);

	return (timingsafe_bcmp(dgst, b->ptr + offset, sizeof(dgst)));
}

static int
large_blob_array_get_tx(fido_dev_t *dev, const size_t offset,
    const size_t count)
{
	fido_blob_t	 f;
	cbor_item_t	*argv[3];
	int		 r;

	memset(argv, 0, sizeof(argv));
	memset(&f, 0, sizeof(f));

	if ((argv[0] = cbor_encode_canonical_uint(count)) == NULL ||
	    (argv[2] = cbor_encode_canonical_uint(offset)) == NULL) {
		fido_log_debug("%s: cbor_encode_uint", __func__);
		r = FIDO_ERR_INTERNAL;
		goto fail;
	}

	if (cbor_build_frame(CTAP_CBOR_LARGE_BLOBS, argv, nitems(argv), &f) < 0 ||
	    fido_tx(dev, CTAP_CMD_CBOR, f.ptr, f.len) < 0) {
		fido_log_debug("%s: fido_tx", __func__);
		r = FIDO_ERR_TX;
		goto fail;
	}

	r = FIDO_OK;
fail:
	cbor_vector_free(argv, nitems(argv));
	free(f.ptr);

	return (r);
}

static int
large_blob_array_get_rx(fido_dev_t *dev, fido_blob_t **frag, int ms)
{
	unsigned char	reply[FIDO_MAXMSG];
	int		reply_len;
	int		r;

	if ((reply_len = fido_rx(dev, CTAP_CMD_CBOR, &reply, sizeof(reply),
	    ms)) < 0) {
		fido_log_debug("%s: fido_rx", __func__);
		r = FIDO_ERR_RX;
		goto fail;
	}

	if (((*frag) = fido_blob_new()) == NULL) {
		fido_log_debug("%s: fido_blob_new", __func__);
		r = FIDO_ERR_INTERNAL;
		goto fail;
	}

	if ((r = cbor_parse_reply(reply, (size_t)reply_len, *frag,
	    parse_large_blob_reply)) != FIDO_OK) {
		fido_log_debug("%s: parse_large_blob_reply", __func__);
		goto fail;
	}

	r = FIDO_OK;

fail:
	return (r);
}

static cbor_item_t *
large_blob_array_load(const uint8_t *ptr, size_t len)
{
	struct cbor_load_result	 cbor;
	cbor_item_t		*item = NULL;

	if ((item = cbor_load(ptr, len, &cbor)) == NULL) {
		if (cbor.error.code == CBOR_ERR_MEMERROR)
			return (NULL);
	} else if (cbor_isa_array(item) && cbor_array_is_definite(item))
		return (item);

	return (cbor_new_definite_array(0));
}

static cbor_item_t *
large_blob_array_get_wait(fido_dev_t *dev, int ms)
{
	fido_blob_t	*arr = NULL;
	fido_blob_t	*frag = NULL;
	cbor_item_t	*item = NULL;
	size_t		 last;
	size_t		 maxlen;

	if ((maxlen = max_fragment_length(dev)) == 0 ||
	    (arr = fido_blob_new()) == NULL) {
		fido_log_debug("%s: maxlen=%zu, arr=%p", __func__, maxlen,
		    (void *)arr);
		goto fail;
	}

	last = maxlen;

	while (last == maxlen) {
		fido_blob_free(&frag);

		if ((large_blob_array_get_tx(dev, arr->len, maxlen)) != FIDO_OK ||
		    (large_blob_array_get_rx(dev, &frag, ms)) != FIDO_OK) {
			fido_log_debug("%s: large_blob_array_get_{tx,rx}, offset=%zu",
			    __func__, arr->len);
			goto fail;
		}

		if (!fido_blob_is_empty(frag) &&
		    fido_blob_append(arr, frag->ptr, frag->len) < 0) {
			fido_log_debug("%s: fido_blob_append", __func__);
			goto fail;
		}

		last = frag->len;
	}

	if (validate_large_blob_array(arr) == 0) {
		item = large_blob_array_load(arr->ptr,
		    arr->len - LARGE_BLOBS_DIGEST_LENGTH);
	} else {
		item = cbor_new_definite_array(0);
	}

fail:
	fido_blob_free(&frag);
	fido_blob_free(&arr);

	return (item);
}

static int
large_blob_do_decode(const cbor_item_t *key, const cbor_item_t *val, void *arg)
{
	large_blob_t	*blob = arg;
	uint64_t	 orig_size;

	if (cbor_isa_uint(key) == false ||
	    cbor_int_get_width(key) != CBOR_INT_8) {
		fido_log_debug("%s: cbor type", __func__);
		return (0); /* ignore */
	}

	switch (cbor_get_uint8(key)) {
	case 1: /* ciphertext */
		if (fido_blob_decode(val, &blob->ct) < 0 ||
		    blob->ct.len < LARGE_BLOBS_TAG_LENGTH)
			return(-1);
		return (0);
	case 2: /* nonce */
		if (fido_blob_decode(val, &blob->iv) < 0 ||
		    blob->iv.len != LARGE_BLOBS_IV_LENGTH)
			return(-1);
		return (0);
	case 3: /* origSize */
		if (!cbor_isa_uint(val) ||
		    (orig_size = cbor_get_int(val)) > SIZE_MAX)
			return (-1);
		blob->sz = (size_t)orig_size;
		return (0);
	default: /* ignore */
		fido_log_debug("%s: cbor value", __func__);
		return (0);
	}
}

static int
large_blob_decode(large_blob_t *blob, const cbor_item_t *item)
{
	if (!cbor_isa_map(item) || !cbor_map_is_definite(item) ||
	    cbor_map_iter(item, blob, large_blob_do_decode) < 0)
		return (-1);

	if (fido_blob_is_empty(&blob->ct) ||
	    fido_blob_is_empty(&blob->iv) ||
	    blob->sz == 0)
		return (-1);

	return (0);
}

static cbor_item_t *
large_blob_encode(const fido_blob_t *pt, const fido_blob_t *key)
{
	large_blob_t	*blob = NULL;
	cbor_item_t	*item = NULL;
	cbor_item_t	*argv[3];

	memset(argv, 0, sizeof(argv));

	if ((blob = large_blob_new()) == NULL ||
	    large_blob_comp_enc(blob, pt, key) < 0) {
		fido_log_debug("%s: large_blob_comp_enc", __func__);
		goto fail;
	}

	if ((argv[0] = fido_blob_encode(&blob->ct)) == NULL ||
	    (argv[1] = fido_blob_encode(&blob->iv)) == NULL ||
	    (argv[2] = cbor_encode_canonical_uint(blob->sz)) == NULL) {
		fido_log_debug("%s: cbor", __func__);
		goto fail;
	}

	item = cbor_flatten_vector(argv, nitems(argv));

fail:
	cbor_vector_free(argv, nitems(argv));
	large_blob_free(&blob);
	return (item);
}

static int
large_blob_array_find(size_t *index, fido_blob_t *out,
    const fido_blob_t *key, const cbor_item_t *arr)
{
	cbor_item_t	*map = NULL;
	fido_blob_t	*pt = NULL;
	large_blob_t	*blob = NULL;
	int		 r = FIDO_ERR_NOTFOUND;


	if ((blob = large_blob_new()) == NULL) {
		fido_log_debug("%s: large_blob_new", __func__);
		r = FIDO_ERR_INTERNAL;
		goto fail;
	}

	for (size_t i = 0; i < cbor_array_size(arr); i++) {
		map = cbor_array_handle(arr)[i];
		if (large_blob_decode(blob, map) == 0 &&
		    (pt = large_blob_pt(blob, key)) != NULL) {
			*index = i;
			r = FIDO_OK;
			break;
		}

		large_blob_reset(blob);
	}

	if (r == FIDO_OK && out != NULL &&
	    (r = fido_uncompress(out, pt, blob->sz)) != FIDO_OK) {
		fido_log_debug("%s: fido_uncompress", __func__);
		goto fail;
	}

fail:
	large_blob_free(&blob);
	fido_blob_free(&pt);
	return (r);
}

static int
large_blob_array_insert(cbor_item_t **arr_p, const fido_blob_t *key,
    cbor_item_t *blob)
{
	cbor_item_t	*old = *arr_p;
	cbor_item_t	*new = NULL;
	size_t		 index;
	int		 r;

	r = large_blob_array_find(&index, NULL, key, old);

	switch (r) {
	case FIDO_OK:
		if (!cbor_array_replace(old, index, blob)) {
			r = FIDO_ERR_INTERNAL;
			goto fail;
		}
		break;
	case FIDO_ERR_NOTFOUND:
		if ((new = cbor_new_definite_array(
		    cbor_array_size(old) + 1)) == NULL) {
			r = FIDO_ERR_INTERNAL;
			goto fail;
		}
		if (cbor_array_copy(new, old) < 0 ||
		    !cbor_array_push(new, blob)) {
			r = FIDO_ERR_INTERNAL;
			cbor_decref(&new);
			goto fail;
		}

		cbor_decref(&old);
		*arr_p = new;
		break;
	default:
		goto fail;
	}

	r = FIDO_OK;
fail:
	return (r);
}

static int
large_blob_array_remove(cbor_item_t **arr_p, const fido_blob_t *key)
{
	cbor_item_t	*arr = *arr_p;
	size_t		 index;
	int		 r;

	r = large_blob_array_find(&index, NULL, key, arr);
	switch (r) {
	case FIDO_OK:
		if (cbor_array_remove(arr_p, index) < 0) {
		    r = FIDO_ERR_INTERNAL;
		    goto fail;
		}
		break;
	case FIDO_ERR_NOTFOUND:
		/* key not found, so let's say it's removed */
		break;
	default:
		goto fail;
	}

	r = FIDO_OK;
fail:
	return (r);
}

int
fido_dev_large_blob_get(fido_dev_t *dev, const unsigned char *key_ptr,
    size_t key_len, fido_blob_t *blob)
{
	fido_blob_t	*key = NULL;
	cbor_item_t	*arr = NULL;
	size_t		 index;
	int		 r;

	if (blob == NULL || key_ptr == NULL || key_len != 32) {
		fido_log_debug("%s: blob=%p, key_ptr=%p, key_len=%zu",
		    __func__, (void *)blob, (const void *)key_ptr, key_len);
		r = FIDO_ERR_INVALID_ARGUMENT;
		goto fail;
	}

	fido_blob_reset(blob);

	if ((key = fido_blob_new()) == NULL ||
	     fido_blob_set(key, key_ptr, key_len) < 0) {
		fido_log_debug("%s: fido_blob_set", __func__);
		r = FIDO_ERR_INTERNAL;
		goto fail;
	}

	if ((arr = large_blob_array_get_wait(dev, -1)) == NULL) {
		fido_log_debug("%s: large_blob_array_get_wait", __func__);
		r = FIDO_ERR_INTERNAL;
		goto fail;
	}

	if ((r = large_blob_array_find(&index, blob, key, arr)) != FIDO_OK) {
		fido_log_debug("%s: large_blob_array_find", __func__);
		goto fail;
	}

fail:
	fido_blob_free(&key);

	if (arr != NULL)
		cbor_decref(&arr);

	return (r);
}

static int
large_blob_array_set_tx(fido_dev_t *dev, const fido_blob_t *token,
    const unsigned char *frag, const size_t len, const size_t offset,
    const size_t total)
{
	fido_blob_t	*hmac = NULL;
	fido_blob_t	 f;
	cbor_item_t	*argv[6];
	int		 r;

	memset(argv, 0, sizeof(argv));
	memset(&f, 0, sizeof(f));

	if ((argv[1] = cbor_build_bytestring(frag, len)) == NULL ||
	    (argv[2] = cbor_encode_canonical_uint(offset)) == NULL) {
		fido_log_debug("%s: cbor_encode_canonical_uint 1", __func__);
		r = FIDO_ERR_INTERNAL;
		goto fail;
	}

	if ((offset == 0) &&
	    (argv[3] = cbor_encode_canonical_uint(total)) == NULL) {
		fido_log_debug("%s: cbor_encode_canonical_uint 2", __func__);
		r = FIDO_ERR_INTERNAL;
		goto fail;
	}

	if (token != NULL) {
		if ((hmac = fido_blob_new()) == NULL ||
		    (prepare_hmac(offset, frag, len, hmac)) ||
		    (argv[4] = cbor_encode_pin_auth(dev, token, hmac)) == NULL ||
		    (argv[5] = cbor_encode_pin_opt(dev)) == NULL) {
			fido_log_debug("%s: cbor_encode_pin_auth", __func__);
			r = FIDO_ERR_INTERNAL;
			goto fail;
		}
	}

	if (cbor_build_frame(CTAP_CBOR_LARGE_BLOBS, argv, nitems(argv), &f) < 0 ||
	    fido_tx(dev, CTAP_CMD_CBOR, f.ptr, f.len) < 0) {
		fido_log_debug("%s: fido_tx", __func__);
		r = FIDO_ERR_TX;
		goto fail;
	}

	r = FIDO_OK;
fail:
	cbor_vector_free(argv, nitems(argv));
	fido_blob_free(&hmac);
	free(f.ptr);

	return (r);
}

static int
large_blob_array_set_wait(fido_dev_t *dev, const cbor_item_t *arr,
    const char *pin, int ms)
{
	unsigned char	 dgst[SHA256_DIGEST_LENGTH];
	fido_blob_t	*token = NULL;
	fido_blob_t	*ecdh = NULL;
	es256_pk_t	*pk = NULL;
	unsigned char	*cbor = NULL;
	size_t		 cbor_len;
	size_t		 cbor_alloc_len;
	size_t		 offset = 0;
	size_t		 maxlen = 0;
	SHA256_CTX	 ctx;
	int		 r;

	if ((maxlen = max_fragment_length(dev)) == 0) {
		fido_log_debug("%s: maxlen=%zu", __func__, maxlen);
		r = FIDO_ERR_INTERNAL;
		goto fail;
	}

	if ((cbor_len = cbor_serialize_alloc(arr, &cbor, &cbor_alloc_len)) == 0 ||
	    cbor_len > (SIZE_MAX - LARGE_BLOBS_DIGEST_LENGTH)) {
		fido_log_debug("%s: cbor_serialize_alloc", __func__);
		r = FIDO_ERR_INTERNAL;
		goto fail;
	}

	if (fido_dev_can_get_uv_token(dev, pin, FIDO_OPT_OMIT)) {
		if ((token = fido_blob_new()) == NULL) {
			fido_log_debug("%s: fido_blob_new", __func__);
			r = FIDO_ERR_INTERNAL;
			goto fail;
		}

		if ((r = fido_do_ecdh(dev, &pk, &ecdh)) != FIDO_OK ||
		    (r = fido_dev_get_uv_token(dev, CTAP_CBOR_LARGE_BLOBS, pin, ecdh, pk,
		    NULL, token)) != FIDO_OK) {
			fido_log_debug("%s: fido_dev_get_uv_token", __func__);
			goto fail;
		}
	}

	if (SHA256_Init(&ctx) == 0) {
		fido_log_debug("%s: SHA256_Init", __func__);
		r = FIDO_ERR_INTERNAL;
		goto fail;
	}

	while (offset < cbor_len) {
		size_t len = maxlen < cbor_len - offset ?
		    maxlen : cbor_len - offset;
		if (SHA256_Update(&ctx, cbor + offset, len) == 0) {
			fido_log_debug("%s: SHA256_Update", __func__);
			r = FIDO_ERR_INTERNAL;
			goto fail;
		}

		if ((r = large_blob_array_set_tx(dev, token,
		    cbor + offset, len, offset,
		    cbor_len + LARGE_BLOBS_DIGEST_LENGTH)) != FIDO_OK ||
		    (r = fido_rx_cbor_status(dev, ms)) != FIDO_OK) {
			fido_log_debug("%s: large_blob_array_set_tx 1",
			    __func__);
			goto fail;
		}

		offset += len;
	}

	if (SHA256_Final(dgst, &ctx) == 0) {
		fido_log_debug("%s: SHA256_Final", __func__);
		r = FIDO_ERR_INTERNAL;
		goto fail;
	}

	if ((r = large_blob_array_set_tx(dev, token, dgst,
	    LARGE_BLOBS_DIGEST_LENGTH, offset,
	    cbor_len + LARGE_BLOBS_DIGEST_LENGTH)) != FIDO_OK ||
	    (r = fido_rx_cbor_status(dev, ms)) != FIDO_OK) {
		fido_log_debug("%s: large_blob_array_set_tx 2", __func__);
		goto fail;
	}

	r = FIDO_OK;

fail:
	fido_blob_free(&token);
	fido_blob_free(&ecdh);
	es256_pk_free(&pk);
	free(cbor);

	return (r);
}

int
fido_dev_large_blob_put(fido_dev_t *dev, const unsigned char *key_ptr,
    size_t key_len, const fido_blob_t *blob, const char *pin)
{
	cbor_item_t	*arr = NULL;
	cbor_item_t	*item = NULL;
	fido_blob_t	*key = NULL;
	int		 r;

	if (blob == NULL || fido_blob_is_empty(blob) ||
	    key_ptr == NULL || key_len != 32) {
		fido_log_debug("%s: blob=%p, key_ptr=%p, key_len=%zu",
		    __func__, (const void *)blob, (const void *)key_ptr, key_len);
		r = FIDO_ERR_INVALID_ARGUMENT;
		goto fail;
	}

	if ((key = fido_blob_new()) == NULL ||
	    fido_blob_set(key, key_ptr, key_len) < 0) {
		fido_log_debug("%s: fido_blob_new", __func__);
		r = FIDO_ERR_INTERNAL;
		goto fail;
	}

	if ((item = large_blob_encode(blob, key)) == NULL ||
	    (arr = large_blob_array_get_wait(dev, -1)) == NULL) {
		fido_log_debug("%s: large_blob_array_get_wait", __func__);
		r = FIDO_ERR_INTERNAL;
		goto fail;
	}

	if ((r = large_blob_array_insert(&arr, key, item)) != FIDO_OK ||
	    (r = large_blob_array_set_wait(dev, arr, pin, -1)) != FIDO_OK) {
		fido_log_debug("%s: large_blob_array_set_wait", __func__);
		goto fail;
	}

	r = FIDO_OK;
fail:
	fido_blob_free(&key);
	if (arr != NULL)
		cbor_decref(&arr);
	if (item != NULL)
		cbor_decref(&item);

	return (r);
}

int
fido_dev_large_blob_remove(fido_dev_t *dev, const unsigned char *key_ptr,
    size_t key_len, const char *pin)
{
	cbor_item_t	*arr = NULL;
	fido_blob_t	*key = NULL;
	int		 r;

	if (key_ptr == NULL || key_len != 32) {
		fido_log_debug("%s: key_ptr = %p, key_len = %zu",
			__func__, (const void *)key_ptr, key_len);
		r = FIDO_ERR_INVALID_ARGUMENT;
		goto fail;
	}

	if ((key = fido_blob_new()) == NULL ||
	    fido_blob_set(key, key_ptr, key_len) < 0) {
		fido_log_debug("%s: fido_blob_set", __func__);
		r = FIDO_ERR_INTERNAL;
		goto fail;
	}

	if ((arr = large_blob_array_get_wait(dev, -1)) == NULL) {
		fido_log_debug("%s: large_blob_array_get_wait", __func__);
		r = FIDO_ERR_INTERNAL;
		goto fail;
	}

	if ((r = large_blob_array_remove(&arr, key)) != FIDO_OK ||
	    (r = large_blob_array_set_wait(dev, arr, pin, -1)) != FIDO_OK) {
		fido_log_debug("%s: large_blob_array_set_wait", __func__);
		goto fail;
	}

	r = FIDO_OK;
fail:
	fido_blob_free(&key);
	if (arr != NULL)
		cbor_decref(&arr);

	return (r);
}

static int
list_large_blob_keys(fido_dev_t *dev, fido_blob_array_t *keys, const char *pin)
{
	fido_credman_rp_t	*rp = NULL;
	fido_credman_rk_t	*rk = NULL;
	const fido_cred_t	*cred = NULL;
	fido_blob_t		*list_ptr = NULL;
	const unsigned char	*ptr = NULL;
	size_t			 len;
	int			 r;

	if ((rp = fido_credman_rp_new()) == NULL) {
		r = FIDO_ERR_INTERNAL;
		goto fail;
	}

	if ((r = fido_credman_get_dev_rp(dev, rp, pin)) != FIDO_OK)
		goto fail;

	for (size_t i = 0; i < fido_credman_rp_count(rp); i++) {
		if ((rk = fido_credman_rk_new()) == NULL) {
			r = FIDO_ERR_INTERNAL;
			goto fail;
		}

		if ((r = fido_credman_get_dev_rk(dev, fido_credman_rp_id(rp, i), rk,
		    pin)) != FIDO_OK)
			goto fail;

		for (size_t j = 0; j < fido_credman_rk_count(rk); j++)
			if ((cred = fido_credman_rk(rk, j)) != NULL &&
			    (ptr = fido_cred_large_blob_key_ptr(cred)) != NULL &&
			    (len = fido_cred_large_blob_key_len(cred)) != 0) {
				if ((list_ptr = recallocarray(keys->ptr, keys->len, keys->len + 1,
				    sizeof(fido_blob_t))) == NULL) {
					r = FIDO_ERR_INTERNAL;
					goto fail;
				}

				keys->ptr = list_ptr;

				if (fido_blob_set(&keys->ptr[keys->len++], ptr, len) < 0) {
					r = FIDO_ERR_INTERNAL;
					goto fail;
				}
			}

		fido_credman_rk_free(&rk);
	}

	r = FIDO_OK;

fail:
	fido_credman_rp_free(&rp);
	fido_credman_rk_free(&rk);

	return (r);
}

static int
remove_unknown_blobs(cbor_item_t **arr, const fido_blob_array_t *keys)
{
	cbor_item_t	*new = NULL;
	cbor_item_t	*elem = NULL;
	large_blob_t	*blob = NULL;
	fido_blob_t	*pt = NULL;
	size_t		 n;
	int		 r;

	n  = cbor_array_size(*arr);
	if ((blob = large_blob_new()) == NULL ||
	    (new = cbor_new_definite_array(n)) == NULL) {
		r = FIDO_ERR_INTERNAL;
		goto fail;
	}

	/* For every element in the array ...*/
	for (size_t i = 0; i < n; i++) {
		/* ... attempt to decode it ... */
		elem = cbor_array_handle(*arr)[i];
		if (large_blob_decode(blob, elem) == 0) {
			/* ... and to decrypt it using every key. */
			for (size_t j = 0; j < keys->len; ++j)
				if ((pt = large_blob_pt(blob, &keys->ptr[j])) != NULL)
					break;

			/* unsuccessful decryption means it's up for removal,
			 * mark it as such by setting it to NULL. */
			if (pt == NULL)
				elem = NULL;

			large_blob_reset(blob);
			fido_blob_free(&pt);
		}

		/* note that non-conformant blobs are kept, as per spec */
		if (elem != NULL && !cbor_array_push(new, elem)) {
			fido_log_debug("%s: cbor_array_push", __func__);
			r = FIDO_ERR_INTERNAL;
			goto fail;
		}
	}

	cbor_decref(arr);
	*arr = new;

	r = FIDO_OK;

fail:
	if (r != FIDO_OK && new != NULL)
		cbor_decref(&new);
	large_blob_free(&blob);

	return (r);
}

int
fido_dev_large_blob_trim(fido_dev_t *dev, const char *pin)
{
	fido_blob_array_t	 keys;
	cbor_item_t		*arr = NULL;
	int			 r;

	memset(&keys, 0, sizeof(keys));

	if ((r = list_large_blob_keys(dev, &keys, pin)) != FIDO_OK) {
		fido_log_debug("%s: list_large_blob_keys", __func__);
		goto fail;
	}

	if ((arr = large_blob_array_get_wait(dev, -1)) == NULL) {
		fido_log_debug("%s: large_blob_array_get_wait", __func__);
		r = FIDO_ERR_INTERNAL;
		goto fail;
	}

	if ((r = remove_unknown_blobs(&arr, &keys)) != FIDO_OK ||
	    (r = large_blob_array_set_wait(dev, arr, pin, -1)) != FIDO_OK) {
		fido_log_debug("%s: large_blob_array_set_wait", __func__);
		goto fail;
	}

	r = FIDO_OK;
fail:
	fido_free_blob_array(&keys);
	if (arr != NULL)
	    cbor_decref(&arr);

	return (r);
}
