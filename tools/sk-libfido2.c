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
#include <stdio.h>
#include <stddef.h>
#include <stdarg.h>

#include <openssl/opensslv.h>
#include <openssl/crypto.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>

#include <fido.h>

#define MAX_FIDO_DEVICES	256

/* Compatibility with OpenSSH 1.0.x */
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
#define ECDSA_SIG_get0(sig, pr, ps) \
	do { \
		(*pr) = sig->r; \
		(*ps) = sig->s; \
	} while (0)
#endif

#define SK_VERSION_MAJOR	0x00020000 /* current API version */

/* Flags */
#define SK_USER_PRESENCE_REQD	0x01

/* Algs */
#define	SK_ECDSA		0x00
#define	SK_ED25519		0x01

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
int sk_enroll(int alg, const uint8_t *challenge, size_t challenge_len,
    const char *application, uint8_t flags,
    struct sk_enroll_response **enroll_response);

/* Sign a challenge */
int sk_sign(int alg, const uint8_t *message, size_t message_len,
    const char *application, const uint8_t *key_handle, size_t key_handle_len,
    uint8_t flags, struct sk_sign_response **sign_response);

/* #define SK_DEBUG 1 */

#ifdef SK_DEBUG
static void skdebug(const char *func, const char *fmt, ...)
    __attribute__((__format__ (printf, 2, 3)));

static void
skdebug(const char *func, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "%s: ", func);
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
	va_end(ap);
}
#else
#define skdebug(...) do { /* nothing */ } while (0)
#endif /* SK_DEBUG */

uint32_t
sk_api_version(void)
{
	return SK_VERSION_MAJOR;
}

/* Select the first identified FIDO device attached to the system */
static char *
pick_first_device(void)
{
	char *ret = NULL;
	fido_dev_info_t *devlist = NULL;
	size_t olen = 0;
	int r;
	const fido_dev_info_t *di;

	if ((devlist = fido_dev_info_new(1)) == NULL) {
		skdebug(__func__, "fido_dev_info_new failed");
		goto out;
	}
	if ((r = fido_dev_info_manifest(devlist, 1, &olen)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_info_manifest failed: %s",
		    fido_strerr(r));
		goto out;
	}
	if (olen != 1) {
		skdebug(__func__, "fido_dev_info_manifest bad len %zu", olen);
		goto out;
	}
	di = fido_dev_info_ptr(devlist, 0);
	if ((ret = strdup(fido_dev_info_path(di))) == NULL) {
		skdebug(__func__, "fido_dev_info_path failed");
		goto out;
	}
 out:
	fido_dev_info_free(&devlist, 1);
	return ret;
}

/*
 * The key returned via fido_cred_pubkey_ptr() is in affine coordinates,
 * but the API expects a SEC1 octet string.
 */
static int
pack_public_key_ecdsa(fido_cred_t *cred, struct sk_enroll_response *response)
{
	const uint8_t *ptr;
	BIGNUM *x = NULL, *y = NULL;
	EC_POINT *q = NULL;
	EC_GROUP *g = NULL;
	BN_CTX *bn_ctx = NULL;
	int ret = -1;

	response->public_key = NULL;
	response->public_key_len = 0;

	if ((bn_ctx = BN_CTX_new()) == NULL ||
	    (x = BN_CTX_get(bn_ctx)) == NULL ||
	    (y = BN_CTX_get(bn_ctx)) == NULL ||
	    (g = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)) == NULL ||
	    (q = EC_POINT_new(g)) == NULL) {
		skdebug(__func__, "libcrypto setup failed");
		goto out;
	}
	if ((ptr = fido_cred_pubkey_ptr(cred)) == NULL) {
		skdebug(__func__, "fido_cred_pubkey_ptr failed");
		goto out;
	}
	if (fido_cred_pubkey_len(cred) != 64) {
		skdebug(__func__, "bad fido_cred_pubkey_len %zu",
		    fido_cred_pubkey_len(cred));
		goto out;
	}

	if (BN_bin2bn(ptr, 32, x) == NULL ||
	    BN_bin2bn(ptr + 32, 32, y) == NULL) {
		skdebug(__func__, "BN_bin2bn failed");
		goto out;
	}
	if (EC_POINT_set_affine_coordinates_GFp(g, q, x, y, bn_ctx) != 1) {
		skdebug(__func__, "EC_POINT_set_affine_coordinates_GFp failed");
		goto out;
	}
	response->public_key_len = EC_POINT_point2oct(g, q,
	    POINT_CONVERSION_UNCOMPRESSED, NULL, 0, bn_ctx);
	if (response->public_key_len == 0 || response->public_key_len > 2048) {
		skdebug(__func__, "bad pubkey length %zu",
		    response->public_key_len);
		goto out;
	}
	if ((response->public_key = malloc(response->public_key_len)) == NULL) {
		skdebug(__func__, "malloc pubkey failed");
		goto out;
	}
	if (EC_POINT_point2oct(g, q, POINT_CONVERSION_UNCOMPRESSED,
	    response->public_key, response->public_key_len, bn_ctx) == 0) {
		skdebug(__func__, "EC_POINT_point2oct failed");
		goto out;
	}
	/* success */
	ret = 0;
 out:
	if (ret != 0 && response->public_key != NULL) {
		memset(response->public_key, 0, response->public_key_len);
		free(response->public_key);
		response->public_key = NULL;
	}
	EC_POINT_free(q);
	EC_GROUP_free(g);
	BN_CTX_free(bn_ctx);
	return ret;
}

static int
pack_public_key_ed25519(fido_cred_t *cred, struct sk_enroll_response *response)
{
	const uint8_t *ptr;
	size_t len;
	int ret = -1;

	response->public_key = NULL;
	response->public_key_len = 0;

	if ((len = fido_cred_pubkey_len(cred)) != 32) {
		skdebug(__func__, "bad fido_cred_pubkey_len len %zu", len);
		goto out;
	}
	if ((ptr = fido_cred_pubkey_ptr(cred)) == NULL) {
		skdebug(__func__, "fido_cred_pubkey_ptr failed");
		goto out;
	}
	response->public_key_len = len;
	if ((response->public_key = malloc(response->public_key_len)) == NULL) {
		skdebug(__func__, "malloc pubkey failed");
		goto out;
	}
	memcpy(response->public_key, ptr, len);
	ret = 0;
 out:
	if (ret != 0)
		free(response->public_key);
	return ret;
}

static int
pack_public_key(int alg, fido_cred_t *cred, struct sk_enroll_response *response)
{
	switch(alg) {
	case SK_ECDSA:
		return pack_public_key_ecdsa(cred, response);
	case SK_ED25519:
		return pack_public_key_ed25519(cred, response);
	default:
		return -1;
	}
}

int
sk_enroll(int alg, const uint8_t *challenge, size_t challenge_len,
    const char *application, uint8_t flags,
    struct sk_enroll_response **enroll_reponse)
{
	fido_cred_t *cred = NULL;
	fido_dev_t *dev = NULL;
	const uint8_t *ptr;
	uint8_t user_id[32];
	struct sk_enroll_response *response = NULL;
	size_t len;
	int cose_alg;
	int ret = -1;
	int r;
	char *device = NULL;

	(void)flags; /* XXX; unused */
#ifdef SK_DEBUG
	fido_init(FIDO_DEBUG);
#endif
	if (enroll_reponse == NULL) {
		skdebug(__func__, "enroll_reponse == NULL");
		goto out;
	}
	*enroll_reponse = NULL;
	switch(alg) {
	case SK_ECDSA:
		cose_alg = COSE_ES256;
		break;
	case SK_ED25519:
		cose_alg = COSE_EDDSA;
		break;
	default:
		skdebug(__func__, "unsupported key type %d", alg);
		goto out;
	}
	if ((device = pick_first_device()) == NULL) {
		skdebug(__func__, "pick_first_device failed");
		goto out;
	}
	skdebug(__func__, "using device %s", device);
	if ((cred = fido_cred_new()) == NULL) {
		skdebug(__func__, "fido_cred_new failed");
		goto out;
	}
	memset(user_id, 0, sizeof(user_id));
	if ((r = fido_cred_set_type(cred, cose_alg)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_type: %s", fido_strerr(r));
		goto out;
	}
	if ((r = fido_cred_set_clientdata_hash(cred, challenge,
	    challenge_len)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_clientdata_hash: %s",
		    fido_strerr(r));
		goto out;
	}
	if ((r = fido_cred_set_user(cred, user_id, sizeof(user_id),
	    "openssh", "openssh", NULL)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_user: %s", fido_strerr(r));
		goto out;
	}
	if ((r = fido_cred_set_rp(cred, application, NULL)) != FIDO_OK) {
		skdebug(__func__, "fido_cred_set_rp: %s", fido_strerr(r));
		goto out;
	}
	if ((dev = fido_dev_new()) == NULL) {
		skdebug(__func__, "fido_dev_new failed");
		goto out;
	}
	if ((r = fido_dev_open(dev, device)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_open: %s", fido_strerr(r));
		goto out;
	}
	if ((r = fido_dev_make_cred(dev, cred, NULL)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_make_cred: %s", fido_strerr(r));
		goto out;
	}
	if (fido_cred_x5c_ptr(cred) != NULL) {
		if ((r = fido_cred_verify(cred)) != FIDO_OK) {
			skdebug(__func__, "fido_cred_verify: %s",
			    fido_strerr(r));
			goto out;
		}
	} else {
		skdebug(__func__, "self-attested credential");
		if ((r = fido_cred_verify_self(cred)) != FIDO_OK) {
			skdebug(__func__, "fido_cred_verify_self: %s",
			    fido_strerr(r));
			goto out;
		}
	}
	if ((response = calloc(1, sizeof(*response))) == NULL) {
		skdebug(__func__, "calloc response failed");
		goto out;
	}
	if (pack_public_key(alg, cred, response) != 0) {
		skdebug(__func__, "pack_public_key failed");
		goto out;
	}
	if ((ptr = fido_cred_id_ptr(cred)) != NULL) {
		len = fido_cred_id_len(cred);
		if ((response->key_handle = calloc(1, len)) == NULL) {
			skdebug(__func__, "calloc key handle failed");
			goto out;
		}
		memcpy(response->key_handle, ptr, len);
		response->key_handle_len = len;
	}
	if ((ptr = fido_cred_sig_ptr(cred)) != NULL) {
		len = fido_cred_sig_len(cred);
		if ((response->signature = calloc(1, len)) == NULL) {
			skdebug(__func__, "calloc signature failed");
			goto out;
		}
		memcpy(response->signature, ptr, len);
		response->signature_len = len;
	}
	if ((ptr = fido_cred_x5c_ptr(cred)) != NULL) {
		len = fido_cred_x5c_len(cred);
		if ((response->attestation_cert = calloc(1, len)) == NULL) {
			skdebug(__func__, "calloc attestation cert failed");
			goto out;
		}
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

static int
pack_sig_ecdsa(fido_assert_t *assert, struct sk_sign_response *response)
{
	ECDSA_SIG *sig = NULL;
	const BIGNUM *sig_r, *sig_s;
	const unsigned char *cp;
	size_t sig_len;
	int ret = -1;

	cp = fido_assert_sig_ptr(assert, 0);
	sig_len = fido_assert_sig_len(assert, 0);
	if ((sig = d2i_ECDSA_SIG(NULL, &cp, sig_len)) == NULL) {
		skdebug(__func__, "d2i_ECDSA_SIG failed");
		goto out;
	}
	ECDSA_SIG_get0(sig, &sig_r, &sig_s);
	response->sig_r_len = BN_num_bytes(sig_r);
	response->sig_s_len = BN_num_bytes(sig_s);
	if ((response->sig_r = calloc(1, response->sig_r_len)) == NULL ||
	    (response->sig_s = calloc(1, response->sig_s_len)) == NULL) {
		skdebug(__func__, "calloc signature failed");
		goto out;
	}
	BN_bn2bin(sig_r, response->sig_r);
	BN_bn2bin(sig_s, response->sig_s);
	ret = 0;
 out:
	ECDSA_SIG_free(sig);
	if (ret != 0) {
		free(response->sig_r);
		free(response->sig_s);
		response->sig_r = NULL;
		response->sig_s = NULL;
	}
	return ret;
}

static int
pack_sig_ed25519(fido_assert_t *assert, struct sk_sign_response *response)
{
	const unsigned char *ptr;
	size_t len;
	int ret = -1;

	ptr = fido_assert_sig_ptr(assert, 0);
	len = fido_assert_sig_len(assert, 0);
	if (len != 64) {
		skdebug(__func__, "bad length %zu", len);
		goto out;
	}
	response->sig_r_len = len;
	if ((response->sig_r = calloc(1, response->sig_r_len)) == NULL) {
		skdebug(__func__, "calloc signature failed");
		goto out;
	}
	memcpy(response->sig_r, ptr, len);
	ret = 0;
 out:
	if (ret != 0) {
		free(response->sig_r);
		response->sig_r = NULL;
	}
	return ret;
}

static int
pack_sig(int alg, fido_assert_t *assert, struct sk_sign_response *response)
{
	switch(alg) {
	case SK_ECDSA:
		return pack_sig_ecdsa(assert, response);
	case SK_ED25519:
		return pack_sig_ed25519(assert, response);
	default:
		return -1;
	}
}

int
sk_sign(int alg, const uint8_t *message, size_t message_len,
    const char *application,
    const uint8_t *key_handle, size_t key_handle_len,
    uint8_t flags, struct sk_sign_response **sign_response)
{
	fido_assert_t *assert = NULL;
	fido_dev_t *dev = NULL;
	struct sk_sign_response *response = NULL;
	fido_dev_info_t *devlist = NULL;
	size_t i, devlist_len = 0;
	int ret = -1;
	int r;
	const char *device;

#ifdef SK_DEBUG
	fido_init(FIDO_DEBUG);
#endif

	if (sign_response == NULL) {
		skdebug(__func__, "sign_response == NULL");
		goto out;
	}
	*sign_response = NULL;
	if ((assert = fido_assert_new()) == NULL) {
		skdebug(__func__, "fido_assert_new failed");
		goto out;
	}
	if ((r = fido_assert_set_clientdata_hash(assert, message,
	    message_len)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_clientdata_hash: %s",
		    fido_strerr(r));
		goto out;
	}
	if ((r = fido_assert_set_rp(assert, application)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_rp: %s", fido_strerr(r));
		goto out;
	}
	if ((r = fido_assert_allow_cred(assert, key_handle,
	    key_handle_len)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_allow_cred: %s", fido_strerr(r));
		goto out;
	}
	if ((r = fido_assert_set_up(assert,
	    (flags & SK_USER_PRESENCE_REQD) ?
	    FIDO_OPT_TRUE : FIDO_OPT_FALSE)) != FIDO_OK) {
		skdebug(__func__, "fido_assert_set_up: %s", fido_strerr(r));
		goto out;
	}

	if ((devlist = fido_dev_info_new(MAX_FIDO_DEVICES)) == NULL) {
		skdebug(__func__, "fido_dev_info_new failed");
		goto out;
	}
	if ((r = fido_dev_info_manifest(devlist, MAX_FIDO_DEVICES,
	    &devlist_len)) != FIDO_OK) {
		skdebug(__func__, "fido_dev_info_manifest: %s", fido_strerr(r));
		goto out;
	}
	for (i = 0; i < devlist_len; i++) {
		const fido_dev_info_t *di = fido_dev_info_ptr(devlist, i);

		if ((device = fido_dev_info_path(di)) == NULL) {
			skdebug(__func__, "fido_dev_info_path failed");
			goto out;
		}
		skdebug(__func__, "using device %s", device);
		if ((dev = fido_dev_new()) == NULL) {
			skdebug(__func__, "fido_dev_new failed");
			goto out;
		}
		if ((r = fido_dev_open(dev, device)) != FIDO_OK) {
			skdebug(__func__, "fido_dev_open: %s", fido_strerr(r));
			fido_dev_free(&dev);
			continue;
		}
		if ((r = fido_dev_get_assert(dev, assert, NULL)) == FIDO_OK) {
			skdebug(__func__, "got assertion from device %s",
			    device);
			/* token owns this key handle */
			break;
		} else {
			if (r != FIDO_ERR_NO_CREDENTIALS) {
				skdebug(__func__, "device %s does not own this "
				    "key handle", device);
			} else {
				skdebug(__func__, "fido_dev_get_assert: %s",
				    fido_strerr(r));
			}
			fido_dev_close(dev);
			fido_dev_free(&dev);
			continue;
		}
	}
	if (i >= devlist_len) {
		skdebug(__func__, "no token matched key handle");
		goto out;
	}
	if ((response = calloc(1, sizeof(*response))) == NULL) {
		skdebug(__func__, "calloc response failed");
		goto out;
	}
	response->flags = fido_assert_flags(assert, 0);
	response->counter = fido_assert_sigcount(assert, 0);
	if (pack_sig(alg, assert, response) != 0) {
		skdebug(__func__, "pack_sig failed");
		goto out;
	}
	*sign_response = response;
	response = NULL;
	ret = 0;
 out:
	fido_dev_info_free(&devlist, MAX_FIDO_DEVICES);
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
