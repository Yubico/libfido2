/*
 * Copyright (c) 2019 Markus Friedl
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>

#include <fido.h>

#define SK_VERSION_MAJOR	0x00010000 /* current API version */

/* Flags */
#define SK_USER_PRESENCE_REQD	0x01

struct sk_enroll_response {
	uint8_t *public_key;
	size_t public_key_len;
	uint8_t *key_handle;
	size_t key_handle_len;
	uint8_t *signature;
	size_t signature_len;
	uint8_t *attestation_cert;
	size_t attestation_cert_len;
};

struct sk_sign_response {
	uint8_t flags;
	uint32_t counter;
	uint8_t *sig_r;
	size_t sig_r_len;
	uint8_t *sig_s;
	size_t sig_s_len;
};

/* Return the version of the middleware API */
uint32_t sk_api_version(void);

/* Enroll a U2F key (private key generation) */
int sk_enroll(const uint8_t *challenge, size_t challenge_len,
    const char *application, uint8_t flags,
    struct sk_enroll_response **enroll_response);

/* Sign a challenge */
int sk_sign(const uint8_t *message, size_t message_len,
    const char *application, const uint8_t *key_handle, size_t key_handle_len,
    uint8_t flags, struct sk_sign_response **sign_response);


/* #define SK_DEBUG 1 */

uint32_t
sk_api_version(void)
{
	return SK_VERSION_MAJOR;
}

/* Select the first identified FIDO device attached to the system */
static char *
pick_device(void)
{
	char *ret = NULL;
	fido_dev_info_t *devlist = NULL;
	size_t olen = 0;

	if ((devlist = fido_dev_info_new(1)) == NULL)
		goto out;
	if (fido_dev_info_manifest(devlist, 1, &olen) != FIDO_OK)
		goto out;
	if (olen != 1)
		goto out;
	if ((ret = strdup(fido_dev_info_path(devlist))) == NULL)
		goto out;
 out:
	fido_dev_info_free(&devlist, 1);
	return ret;
}

/*
 * The key returned via fido_cred_pubkey_ptr() is in affine coordinates,
 * but the API expects a SEC1 octet string.
 */
static int
pack_public_key(fido_cred_t *cred, struct sk_enroll_response *response)
{
	const uint8_t *ptr;
	BIGNUM *x = NULL, *y = NULL;
	EC_POINT *q = NULL;
	EC_GROUP *g = NULL;
	BN_CTX *bn_ctx = NULL;
	int success = 0;

	response->public_key = NULL;
	response->public_key_len = 0;

	if ((bn_ctx = BN_CTX_new()) == NULL ||
	    (x = BN_CTX_get(bn_ctx)) == NULL ||
	    (y = BN_CTX_get(bn_ctx)) == NULL ||
	    (g = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)) == NULL ||
	    (q = EC_POINT_new(g)) == NULL)
		goto out;
	if ((ptr = fido_cred_pubkey_ptr(cred)) == NULL)
		goto out;
	if (fido_cred_pubkey_len(cred) != 64)
		goto out;

	if (BN_bin2bn(ptr, 32, x) == NULL ||
	    BN_bin2bn(ptr + 32, 32, y) == NULL)
		goto out;
	if (EC_POINT_set_affine_coordinates_GFp(g, q, x, y, bn_ctx) != 1)
		goto out;
	response->public_key_len = EC_POINT_point2oct(g, q,
	    POINT_CONVERSION_UNCOMPRESSED, NULL, 0, bn_ctx);
	if (response->public_key_len == 0 || response->public_key_len > 2048)
		goto out;
	if ((response->public_key = malloc(response->public_key_len)) == NULL)
		goto out;
	if (EC_POINT_point2oct(g, q, POINT_CONVERSION_UNCOMPRESSED,
            response->public_key, response->public_key_len, bn_ctx) == 0)
		goto out;
	/* success */
	success = 1;
 out:
	if (!success && response->public_key != NULL) {
		memset(response->public_key, 0, response->public_key_len);
		free(response->public_key);
	}
	EC_POINT_free(q);
	EC_GROUP_free(g);
	BN_CTX_free(bn_ctx);
	return success ? 0 : -1;
}

int
sk_enroll(const uint8_t *challenge, size_t challenge_len,
    const char *application, uint8_t flags,
    struct sk_enroll_response **enroll_reponse)
{
	fido_cred_t *cred = NULL;
	fido_dev_t *dev = NULL;
	const uint8_t *ptr;
	struct sk_enroll_response *response = NULL;
	size_t len;
	int ret = -1;
	int r;
	char *device = NULL;

	(void)flags; /* XXX; unused */
#ifdef SK_DEBUF
	fido_init(FIDO_DEBUG);
#endif

	if ((device = pick_device()) == NULL)
		goto out;
	if (enroll_reponse == NULL)
		goto out;
	*enroll_reponse = NULL;
	if ((cred = fido_cred_new()) == NULL)
		goto out;
	if ((r = fido_cred_set_type(cred, COSE_ES256)) != FIDO_OK ||
	    (r = fido_cred_set_clientdata_hash(cred, challenge, challenge_len)) != FIDO_OK ||
	    (r = fido_cred_set_rp(cred, application, NULL)) != FIDO_OK)
		goto out;
	if ((dev = fido_dev_new()) == NULL)
		goto out;
	if ((r = fido_dev_open(dev, device)) != FIDO_OK)
		goto out;
	fido_dev_force_u2f(dev);
	if ((r = fido_dev_make_cred(dev, cred, NULL)) != FIDO_OK)
		goto out;
	if ((r = fido_cred_verify(cred)) != FIDO_OK)
		goto out;
	if ((response = calloc(1, sizeof(*response))) == NULL)
		goto out;
	if (pack_public_key(cred, response) != 0)
		goto out;
	if ((ptr = fido_cred_id_ptr(cred)) != NULL) {
		len = fido_cred_id_len(cred);
		if ((response->key_handle = calloc(1, len)) == NULL)
			goto out;
		memcpy(response->key_handle, ptr, len);
		response->key_handle_len = len;
	}
	if ((ptr = fido_cred_sig_ptr(cred)) != NULL) {
		len = fido_cred_sig_len(cred);
		if ((response->signature = calloc(1, len)) == NULL)
			goto out;
		memcpy(response->signature, ptr, len);
		response->signature_len = len;
	}
	if ((ptr = fido_cred_x5c_ptr(cred)) != NULL) {
		len = fido_cred_x5c_len(cred);
		if ((response->attestation_cert = calloc(1, len)) == NULL)
			goto out;
		memcpy(response->attestation_cert, ptr, len);
		response->attestation_cert_len = len;
	}
	*enroll_reponse = response;
	response = NULL;
	ret = 0;
 out:
	free(device);
	if (response != NULL) {
		free(response->public_key);
		free(response->key_handle);
		free(response->signature);
		free(response->attestation_cert);
		free(response);
	}
	if (dev != NULL) {
		fido_dev_close(dev);
		fido_dev_free(&dev);
	}
	if (cred != NULL) {
		fido_cred_free(&cred);
	}
	return ret;
}

int
sk_sign(const uint8_t *message, size_t message_len, const char *application,
    const uint8_t *key_handle, size_t key_handle_len,
    uint8_t flags, struct sk_sign_response **sign_response)
{
	ECDSA_SIG *sig = NULL;
	const BIGNUM *sig_r, *sig_s;
	const u_char *cp;
	fido_assert_t *assert = NULL;
	fido_dev_t *dev = NULL;
	struct sk_sign_response *response = NULL;
	size_t sig_len;
	int ret = -1;
	int r;
	char *device = NULL;

#ifdef SK_DEBUF
	fido_init(FIDO_DEBUG);
#endif

	if ((device = pick_device()) == NULL)
		goto out;
	if (sign_response == NULL)
		goto out;
	*sign_response = NULL;
	if ((assert = fido_assert_new()) == NULL)
		goto out;
	if ((r = fido_assert_set_clientdata_hash(assert, message, message_len)) != FIDO_OK ||
	    (r = fido_assert_set_rp(assert, application)) != FIDO_OK ||
	    (r = fido_assert_allow_cred(assert, key_handle, key_handle_len)) != FIDO_OK)
		goto out;
	if ((r = fido_assert_set_up(assert,
	    (flags & SK_USER_PRESENCE_REQD) ?
	    FIDO_OPT_TRUE : FIDO_OPT_FALSE)) != FIDO_OK)
		goto out;
	if ((dev = fido_dev_new()) == NULL)
		goto out;
	if ((r = fido_dev_open(dev, device)) != FIDO_OK)
		goto out;
	fido_dev_force_u2f(dev);
	if ((r = fido_dev_get_assert(dev, assert, NULL)) != FIDO_OK)
		goto out;
	if ((response = calloc(1, sizeof(*response))) == NULL)
		goto out;
	response->flags = fido_assert_flags(assert, 0);
	response->counter = fido_assert_sigcount(assert, 0);
	cp = fido_assert_sig_ptr(assert, 0);
	sig_len = fido_assert_sig_len(assert, 0);
	if ((sig = d2i_ECDSA_SIG(NULL, &cp, sig_len)) == NULL)
		goto out;
	ECDSA_SIG_get0(sig, &sig_r, &sig_s);
	response->sig_r_len = BN_num_bytes(sig_r);
	response->sig_s_len = BN_num_bytes(sig_s);
	if ((response->sig_r = calloc(1, response->sig_r_len)) == NULL ||
	    (response->sig_s = calloc(1, response->sig_s_len)) == NULL)
		goto out;
	BN_bn2bin(sig_r, response->sig_r);
	BN_bn2bin(sig_s, response->sig_s);
	*sign_response = response;
	response = NULL;
	ret = 0;
 out:
	free(device);
	ECDSA_SIG_free(sig);
	if (response != NULL) {
		free(response->sig_r);
		free(response->sig_s);
		free(response);
	}
	if (dev != NULL) {
		fido_dev_close(dev);
		fido_dev_free(&dev);
	}
	if (assert != NULL) {
		fido_assert_free(&assert);
	}
	return ret;
}
