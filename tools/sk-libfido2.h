#ifndef THIRD_PARTY_LIBFIDO2_TOOLS_SK_LIBFIDO2_H_
#define THIRD_PARTY_LIBFIDO2_TOOLS_SK_LIBFIDO2_H_

#include <stdlib.h>
#include <stdint.h>

#define SK_VERSION_MAJOR	0x00020000 /* current API version */

/* Return values */
#define SK_SUCCESS 0
#define SK_FAIL    1

/* Flags */
#define TUP_FLAG             0x01
#define INDIVIDUAL_CERT_FLAG 0x80
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

#endif  // THIRD_PARTY_LIBFIDO2_TOOLS_SK_LIBFIDO2_H_
