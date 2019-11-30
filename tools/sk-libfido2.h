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

#ifndef _SK_LIBFIDO2_H_
#define _SK_LIBFIDO2_H_

#include <stdlib.h>
#include <stdint.h>

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
int sk_enroll(int alg, const uint8_t *challenge_hash, size_t challenge_hash_len,
    const char *application, uint8_t flags,
    struct sk_enroll_response **enroll_response);

/* Sign a challenge */
int sk_sign(int alg, const uint8_t *message_hash, size_t message_hash_len,
    const char *application, const uint8_t *key_handle, size_t key_handle_len,
    uint8_t flags, struct sk_sign_response **sign_response);

#endif /* !_SK_LIBFIDO2_H_ */
