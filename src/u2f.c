/*
 * Copyright (c) 2018 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <openssl/sha.h>
#include <openssl/x509.h>

#include <string.h>
#include <unistd.h>
#include "fido.h"

static int
sig_get(fido_blob_t *sig, const unsigned char **buf, size_t *len)
{
	sig->len = *len; /* consume the whole buffer */

	if ((sig->ptr = calloc(1, sig->len)) == NULL ||
	    buf_read(buf, len, sig->ptr, sig->len) < 0) {
		if (sig->ptr != NULL) {
			explicit_bzero(sig->ptr, sig->len);
			free(sig->ptr);
			sig->ptr = NULL;
			sig->len = 0;
			return (-1);
		}
	}

	return (0);
}

static int
x5c_get(fido_blob_t *x5c, const unsigned char **buf, size_t *len)
{
	X509	*cert = NULL;
	int	 ok = -1;

	/* find out the certificate's length */
	const unsigned char *end = *buf;
	if ((cert = d2i_X509(NULL, &end, *len)) == NULL || end <= *buf ||
	    (x5c->len = (size_t)(end - *buf)) >= *len)
		goto fail;

	/* read accordingly */
	if ((x5c->ptr = calloc(1, x5c->len)) == NULL ||
	    buf_read(buf, len, x5c->ptr, x5c->len) < 0)
		goto fail;

	ok = 0;
fail:
	if (cert != NULL)
		X509_free(cert);

	if (ok < 0) {
		free(x5c->ptr);
		x5c->ptr = NULL;
		x5c->len = 0;
	}

	return (ok);
}

static int
authdata_cbor_get(const char *rp_id, uint8_t flags, uint32_t sigcount,
    fido_blob_t *authdata_cbor)
{
	fido_authdata_t	 ad;
	cbor_item_t	*item = NULL;
	int		 ok = -1;

	SHA256((const unsigned char *)rp_id, strlen(rp_id), ad.rp_id_hash);
	ad.flags = flags; /* XXX translate? */
	ad.sigcount = sigcount;

	if ((item = cbor_build_bytestring((const unsigned char *)&ad,
	    sizeof(ad))) == NULL || cbor_serialize_alloc(item,
	    &authdata_cbor->ptr, &authdata_cbor->len) == 0)
		goto fail;

	ok = 0;
fail:
	if (item != NULL)
		cbor_decref(&item);

	return (ok);
}

static int
send_dummy_register(fido_dev_t *dev, int ms)
{
	const uint8_t	 cmd = CTAP_FRAME_INIT | CTAP_CMD_MSG;
	iso7816_apdu_t	*apdu = NULL;
	unsigned char	 challenge[SHA256_DIGEST_LENGTH];
	unsigned char	 application[SHA256_DIGEST_LENGTH];
	unsigned char	 reply[2048];
	int		 r = FIDO_ERR_INTERNAL;

	apdu = iso7816_new(U2F_CMD_REGISTER, 0, 2 * SHA256_DIGEST_LENGTH);
	if (apdu == NULL)
		goto fail;

	/* dummy challenge & application */
	memset(&challenge, 0xff, sizeof(challenge));
	memset(&application, 0xff, sizeof(application));

	if (iso7816_add(apdu, &challenge, sizeof(challenge)) < 0 ||
	    iso7816_add(apdu, &application, sizeof(application)) < 0)
		goto fail;

	do {
		if (tx(dev, cmd, iso7816_ptr(apdu), iso7816_len(apdu)) < 0) {
			r = FIDO_ERR_TX;
			goto fail;
		}
		if (rx(dev, cmd, &reply, sizeof(reply), ms) < 2) {
			r = FIDO_ERR_RX;
			goto fail;
		}
		usleep((ms == -1 ? 500 : ms) * 1000);
	} while (((reply[0] << 8) | reply[1]) == SW_CONDITIONS_NOT_SATISFIED);


	r = FIDO_OK;
fail:
	iso7816_free(&apdu);

	return (r);
}

static int
key_lookup(fido_dev_t *dev, const char *rp_id, const fido_blob_t *key_id,
    int *found, int ms)
{
	const uint8_t	 cmd = CTAP_FRAME_INIT | CTAP_CMD_MSG;
	iso7816_apdu_t	*apdu = NULL;
	unsigned char	 challenge[SHA256_DIGEST_LENGTH];
	unsigned char	 rp_id_hash[SHA256_DIGEST_LENGTH];
	unsigned char	 reply[8];
	uint8_t		 key_id_len;
	int		 r = FIDO_ERR_INTERNAL;

	if (key_id->len > UINT8_MAX || rp_id == NULL) {
		r = FIDO_ERR_INVALID_ARGUMENT;
		goto fail;
	}

	key_id_len = key_id->len;
	apdu = iso7816_new(U2F_CMD_AUTH, U2F_AUTH_CHECK,
	    2 * SHA256_DIGEST_LENGTH + sizeof(key_id_len) + key_id_len);
	if (apdu == NULL)
		goto fail;

	memset(&challenge, 0xff, sizeof(challenge));
	memset(&rp_id_hash, 0, sizeof(rp_id_hash));
	SHA256((const void *)rp_id, strlen(rp_id), rp_id_hash);

	if (iso7816_add(apdu, &challenge, sizeof(challenge)) < 0 ||
	    iso7816_add(apdu, &rp_id_hash, sizeof(rp_id_hash)) < 0 ||
	    iso7816_add(apdu, &key_id_len, sizeof(key_id_len)) < 0 ||
	    iso7816_add(apdu, key_id->ptr, key_id_len) < 0)
		goto fail;

	if (tx(dev, cmd, iso7816_ptr(apdu), iso7816_len(apdu)) < 0) {
		r = FIDO_ERR_TX;
		goto fail;
	}
	if (rx(dev, cmd, &reply, sizeof(reply), ms) != 2) {
		r = FIDO_ERR_RX;
		goto fail;
	}

	switch ((reply[0] << 8) | reply[1]) {
	case SW_CONDITIONS_NOT_SATISFIED:
		*found = 1; /* key exists */
		break;
	case SW_WRONG_DATA:
		*found = 0; /* key does not exist */
		break;
	default:
		/* unexpected sw */
		goto fail;
	}

	r = FIDO_OK;
fail:
	iso7816_free(&apdu);

	return (r);
}

static int
parse_auth_reply(fido_assert_t *assert, size_t idx, const unsigned char *reply,
    size_t len)
{
	fido_blob_t	sig;
	fido_blob_t	authdata;
	uint8_t		flags;
	uint32_t	sigcount;
	int		r;

	memset(&sig, 0, sizeof(sig));
	memset(&authdata, 0, sizeof(authdata));
	r = FIDO_ERR_RX;

	/* check status word */
	if (len < 2 || ((reply[len - 2] << 8) | reply[len - 1]) != SW_NO_ERROR)
		goto fail;
	len -= 2;

	/* fake authdata */
	if (buf_read(&reply, &len, &flags, sizeof(flags)) < 0 ||
	    buf_read(&reply, &len, &sigcount, sizeof(sigcount)) < 0 ||
	    sig_get(&sig, &reply, &len) < 0 || authdata_cbor_get(assert->rp_id,
	     flags, sigcount, &authdata) < 0)
		goto fail;

	/* set the retrieved parameters */
	if ((r = fido_assert_set_authdata(assert, idx, authdata.ptr,
	    authdata.len)) != FIDO_OK || (r = fido_assert_set_sig(assert, idx,
	    sig.ptr, sig.len)) != FIDO_OK)
		goto fail;

	r = FIDO_OK;
fail:
	if (sig.ptr != NULL) {
		explicit_bzero(sig.ptr, sig.len);
		free(sig.ptr);
	}
	if (authdata.ptr != NULL) {
		explicit_bzero(authdata.ptr, authdata.len);
		free(authdata.ptr);
	}

	return (r);
}

static int
do_auth(fido_dev_t *dev, const fido_blob_t *cdh, const char *rp_id,
    const fido_blob_t *key_id, fido_assert_t *assert, size_t idx, int ms)
{
	const uint8_t	 cmd = CTAP_FRAME_INIT | CTAP_CMD_MSG;
	iso7816_apdu_t	*apdu = NULL;
	unsigned char	 rp_id_hash[SHA256_DIGEST_LENGTH];
	unsigned char	 reply[128];
	uint8_t		 key_id_len;
	int		 reply_len;
	int		 r = FIDO_ERR_INTERNAL;

	if (cdh->len != SHA256_DIGEST_LENGTH || key_id->len > UINT8_MAX ||
	    rp_id == NULL) {
		r = FIDO_ERR_INVALID_ARGUMENT;
		goto fail;
	}

	key_id_len = key_id->len;
	apdu = iso7816_new(U2F_CMD_AUTH, U2F_AUTH_SIGN,
	    2 * SHA256_DIGEST_LENGTH + sizeof(key_id_len) + key_id_len);
	if (apdu == NULL)
		goto fail;

	memset(&rp_id_hash, 0, sizeof(rp_id_hash));
	SHA256((const void *)rp_id, strlen(rp_id), rp_id_hash);

	if (iso7816_add(apdu, cdh->ptr, cdh->len) < 0 ||
	    iso7816_add(apdu, &rp_id_hash, sizeof(rp_id_hash)) < 0 ||
	    iso7816_add(apdu, &key_id_len, sizeof(key_id_len)) < 0 ||
	    iso7816_add(apdu, key_id->ptr, key_id_len) < 0)
		goto fail;

	do {
		if (tx(dev, cmd, iso7816_ptr(apdu), iso7816_len(apdu)) < 0) {
			r = FIDO_ERR_TX;
			goto fail;
		}
		if ((reply_len = rx(dev, cmd, &reply, sizeof(reply), ms)) < 2) {
			r = FIDO_ERR_RX;
			goto fail;
		}
		usleep((ms == -1 ? 500 : ms) * 1000);
	} while (((reply[0] << 8) | reply[1]) == SW_CONDITIONS_NOT_SATISFIED);

	/* XXX */
	fido_blob_set(&assert->stmt[idx].id, key_id->ptr, key_id->len);

	r = parse_auth_reply(assert, idx, reply, (size_t)reply_len);
fail:
	iso7816_free(&apdu);

	return (r);
}

static int
encode_cred_authdata(const char *rp_id, const uint8_t *kh, uint8_t kh_len,
    const uint8_t *pubkey, size_t pubkey_len, fido_blob_t *out)
{
	fido_blob_t	 body;
	fido_blob_t	 cred;
	es256_pk_t	*pk = NULL;
	cbor_item_t	*pk_cbor = NULL;
	cbor_item_t	*body_cbor = NULL;
	size_t		 dummy;
	int		 ok = -1;

	memset(&body, 0, sizeof(body));
	memset(&cred, 0, sizeof(cred));
	memset(out, 0, sizeof(*out));

	if (rp_id == NULL)
		goto fail;

	/* encode and serialize pubkey */
	if (pubkey_len != 65 || pubkey[0] != 0x04 ||
	    (pk = es256_pk_new()) == NULL ||
	    es256_pk_set_x(pk, &pubkey[1]) < 0 ||
	    es256_pk_set_y(pk, &pubkey[33]) < 0 ||
	    (pk_cbor = es256_pk_encode(pk)) == NULL ||
	    (cred.len = cbor_serialize_alloc(pk_cbor, &cred.ptr, &dummy)) != 77)
		goto fail;

	body.len = 32 + 1 + 4 + 16 + 2 + kh_len + 77;
	if ((body.ptr = calloc(1, body.len)) == NULL)
		goto fail;
	SHA256((const unsigned char *)rp_id, strlen(rp_id), &body.ptr[0]);
	body.ptr[32] = 0x41; /* hardcoded flags value */
	body.ptr[53] = 0x00;
	body.ptr[54] = kh_len;
	memcpy(&body.ptr[55], kh, kh_len);
	memcpy(&body.ptr[55 + kh_len], cred.ptr, 77);

	if ((body_cbor = fido_blob_encode(&body)) == NULL ||
	    (out->len = cbor_serialize_alloc(body_cbor, &out->ptr,
	    &dummy)) == 0)
		goto fail;

	ok = 0;
fail:
	es256_pk_free(&pk);

	if (pk_cbor != NULL)
		cbor_decref(&pk_cbor);
	if (body_cbor != NULL)
		cbor_decref(&body_cbor);

	if (cred.ptr != NULL) {
		explicit_bzero(cred.ptr, cred.len);
		free(cred.ptr);
	}
	if (body.ptr != NULL) {
		explicit_bzero(body.ptr, body.len);
		free(body.ptr);
	}

	return (ok);
}

static int
parse_register_reply(fido_cred_t *cred, const unsigned char *reply, size_t len)
{
	fido_blob_t	 x5c;
	fido_blob_t	 sig;
	fido_blob_t	 authdata;
	uint8_t		 dummy;
	uint8_t		 pubkey[65];
	uint8_t		 kh_len;
	uint8_t		*kh = NULL;
	int		 r;

	memset(&x5c, 0, sizeof(x5c));
	memset(&sig, 0, sizeof(sig));
	memset(&authdata, 0, sizeof(authdata));
	r = FIDO_ERR_RX;

	/* status word */
	if (len < 2 ||
	    ((reply[len - 2] << 8) | reply[len - 1]) != SW_NO_ERROR)
		goto fail;
	len -= 2;

	/* reserved byte */
	if (buf_read(&reply, &len, &dummy, sizeof(dummy)) < 0 ||
	    dummy != 0x05)
		goto fail;

	/* pubkey + key handle */
	if (buf_read(&reply, &len, &pubkey, sizeof(pubkey)) < 0 ||
	    buf_read(&reply, &len, &kh_len, sizeof(kh_len)) < 0 ||
	    (kh = calloc(1, kh_len)) == NULL ||
	    buf_read(&reply, &len, kh, kh_len) < 0)
		goto fail;

	/* x5c + sig */
	if (x5c_get(&x5c, &reply, &len) < 0 ||
	    sig_get(&sig, &reply, &len) < 0)
		goto fail;

	/* authdata */
	if (encode_cred_authdata(cred->rp.id, kh, kh_len, pubkey,
	    sizeof(pubkey), &authdata) < 0)
		goto fail;

	if ((r = fido_cred_set_fmt(cred, "fido-u2f")) != FIDO_OK ||
	    (r = fido_cred_set_authdata(cred, authdata.ptr, authdata.len)) != FIDO_OK ||
	    (r = fido_cred_set_x509(cred, x5c.ptr, x5c.len)) != FIDO_OK ||
	    (r = fido_cred_set_sig(cred, sig.ptr, sig.len)) != FIDO_OK)
		goto fail;

	r = FIDO_OK;
fail:
	if (kh != NULL) {
		explicit_bzero(kh, kh_len);
		free(kh);
	}
	if (x5c.ptr != NULL) {
		explicit_bzero(x5c.ptr, x5c.len);
		free(x5c.ptr);
	}
	if (sig.ptr != NULL) {
		explicit_bzero(sig.ptr, sig.len);
		free(sig.ptr);
	}
	if (authdata.ptr != NULL) {
		explicit_bzero(authdata.ptr, authdata.len);
		free(authdata.ptr);
	}

	return (r);
}

int
u2f_register(fido_dev_t *dev, fido_cred_t *cred, int ms)
{
	const uint8_t	 cmd = CTAP_FRAME_INIT | CTAP_CMD_MSG;
	iso7816_apdu_t	*apdu = NULL;
	unsigned char	 rp_id_hash[SHA256_DIGEST_LENGTH];
	unsigned char	 reply[2048];
	int		 reply_len;
	int		 found;
	int		 r;

	if (cred->rk || cred->uv)
		return (FIDO_ERR_UNSUPPORTED_OPTION);

	if (cred->cdh.ptr == NULL || cred->cdh.len != SHA256_DIGEST_LENGTH)
		return (FIDO_ERR_INVALID_ARGUMENT);

	for (size_t i = 0; i < cred->excl.len; i++) {
		if ((r = key_lookup(dev, cred->rp.id, &cred->excl.ptr[i],
		    &found, ms)) != FIDO_OK)
			return (r);
		if (found) {
			if ((r = send_dummy_register(dev, ms)) != FIDO_OK)
				return (r);
			return (FIDO_ERR_CREDENTIAL_EXCLUDED);
		}
	}

	apdu = iso7816_new(U2F_CMD_REGISTER, 0, 2 * SHA256_DIGEST_LENGTH);
	if (apdu == NULL) {
		r = FIDO_ERR_INTERNAL;
		goto fail;
	}

	memset(&rp_id_hash, 0, sizeof(rp_id_hash));
	SHA256((const void *)cred->rp.id, strlen(cred->rp.id), rp_id_hash);

	if (iso7816_add(apdu, cred->cdh.ptr, cred->cdh.len) < 0 ||
	    iso7816_add(apdu, rp_id_hash, sizeof(rp_id_hash)) < 0) {
		r = FIDO_ERR_INTERNAL;
		goto fail;
	}

	do {
		if (tx(dev, cmd, iso7816_ptr(apdu), iso7816_len(apdu)) < 0) {
			r = FIDO_ERR_TX;
			goto fail;
		}
		if ((reply_len = rx(dev, cmd, &reply, sizeof(reply), ms)) < 2) {
			r = FIDO_ERR_RX;
			goto fail;
		}
		usleep((ms == -1 ? 500 : ms) * 1000);
	} while (((reply[0] << 8) | reply[1]) == SW_CONDITIONS_NOT_SATISFIED);

	r = parse_register_reply(cred, reply, (size_t)reply_len);
fail:
	iso7816_free(&apdu);

	return (r);

}

int
u2f_authenticate(fido_dev_t *dev, fido_assert_t *assert, int ms)
{
	int	found;
	int	r;

	if (assert->uv || assert->allow_list.ptr == NULL)
		return (FIDO_ERR_UNSUPPORTED_OPTION);

	if ((r = fido_assert_set_count(assert,
	    assert->allow_list.len) != FIDO_OK))
		return (r);

	for (size_t i = 0; i < assert->allow_list.len; i++) {
		if ((r = key_lookup(dev, assert->rp_id,
		    &assert->allow_list.ptr[i], &found, ms)) != FIDO_OK)
			return (r);
		if (found) {
			if ((r = do_auth(dev, &assert->cdh, assert->rp_id,
			    &assert->allow_list.ptr[i], assert, i,
			    ms)) != FIDO_OK)
				return (r); /* XXX */
		}
	}

	return (FIDO_OK);
}
