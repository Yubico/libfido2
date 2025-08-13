/*
 * Copyright (c) 2025 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * Example demonstrating the CTAP2 hmac-secret extension.
 * This shows how to:
 * 1. Create a credential with hmac-secret extension enabled
 * 2. Encrypt a message using PRF-derived key with HKDF + AES-GCM
 * 3. Decrypt the message back to plaintext
 *
 * Usage:
 * prf -M [-P pin] <device>                         # Make credential with PRF support
 * prf -E [-P pin] <device> <cred_id_hex> <message>      # Encrypt message
 * prf -D [-P pin] <device> <cred_id_hex> <ciphertext>   # Decrypt message
 * 
 * This tool serves as a reference implementation for developers building native 
 * applications that require strong, phishing-resistant, client-side encryption. 
 * While this example demonstrates modern cryptographic best practices, it is 
 * intended as an educational example. Developers must perform their own security 
 * reviews and threat modeling to ensure the patterns and cryptographic choices 
 * are appropriate for their specific use case.
 */

#include <errno.h>
#include <fido.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>

#include "../openbsd-compat/openbsd-compat.h"
#include "extern.h"

static const unsigned char cdh[32] = {
    0xf9, 0x64, 0x57, 0xe7, 0x2d, 0x97, 0xf6, 0xbb,
    0xdd, 0xd7, 0xfb, 0x06, 0x37, 0x62, 0xea, 0x26,
    0x20, 0x44, 0x8e, 0x69, 0x7c, 0x03, 0xf2, 0x31,
    0x2f, 0x99, 0xdc, 0xaf, 0x3e, 0x8a, 0x91, 0x6b,
};

static const unsigned char user_id[32] = {
    0x78, 0x1c, 0x78, 0x60, 0xad, 0x88, 0xd2, 0x63,
    0x32, 0x62, 0x2a, 0xf1, 0x74, 0x5d, 0xed, 0xb2,
    0xe7, 0xa4, 0x2b, 0x44, 0x89, 0x29, 0x39, 0xc5,
    0x56, 0x64, 0x01, 0x27, 0x0d, 0xbb, 0xc4, 0x49,
};

static void
usage(void)
{
    fprintf(stderr, "usage: prf -M [-P pin] <device>\n");
    fprintf(stderr, "       prf -E [-P pin] <device> <cred_id_hex> <message>\n");
    fprintf(stderr, "       prf -D [-P pin] <device> <cred_id_hex> <ciphertext_hex>\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "  -M          make a new PRF-capable credential\n");
    fprintf(stderr, "  -E          encrypt a message using a PRF-derived key\n");
    fprintf(stderr, "  -D          decrypt a message using a PRF-derived key\n");
    fprintf(stderr, "  -P pin      use PIN for authentication\n");
    exit(EXIT_FAILURE);
}

static void
print_hex(const char *label, const unsigned char *ptr, size_t len)
{
    size_t i;

    printf("%s", label);
    for (i = 0; i < len; i++) {
        printf("%02x", ptr[i]);
    }
    printf("\n");
}

static unsigned char *
hex_decode(const char *hex_str, size_t *len)
{
    size_t hex_len = strlen(hex_str);
    unsigned char *buf;
    size_t i;

    if (hex_len % 2 != 0)
        errx(1, "hex string must have even length");

    *len = hex_len / 2;
    if ((buf = malloc(*len)) == NULL)
        errx(1, "malloc");

    for (i = 0; i < *len; i++) {
        if (sscanf(hex_str + i * 2, "%2hhx", &buf[i]) != 1)
            errx(1, "invalid hex character");
    }

    return buf;
}

static unsigned char *
get_prf_secret(const char *device_path, const unsigned char *cred_id, size_t cred_id_len, const char *pin)
{
    fido_dev_t *dev;
    fido_assert_t *assert;
    unsigned char salt[32];
    unsigned char *secret;
    int r;

    /* Create application-specific salt */
    memset(salt, 0, sizeof(salt));
    strcpy((char *)salt, "my-app-encryption-v1");

    if ((dev = fido_dev_new()) == NULL)
        errx(1, "fido_dev_new");
    if ((r = fido_dev_open(dev, device_path)) != FIDO_OK)
        errx(1, "fido_dev_open: %s (0x%x)", fido_strerr(r), r);

    if ((assert = fido_assert_new()) == NULL)
        errx(1, "fido_assert_new");

    /* Set assertion parameters */
    if ((r = fido_assert_set_clientdata_hash(assert, cdh, sizeof(cdh))) != FIDO_OK)
        errx(1, "fido_assert_set_clientdata_hash: %s (0x%x)", fido_strerr(r), r);
    if ((r = fido_assert_set_rp(assert, "localhost")) != FIDO_OK)
        errx(1, "fido_assert_set_rp: %s (0x%x)", fido_strerr(r), r);
    if ((r = fido_assert_allow_cred(assert, cred_id, cred_id_len)) != FIDO_OK)
        errx(1, "fido_assert_allow_cred: %s (0x%x)", fido_strerr(r), r);

    /* Enable hmac-secret extension and set salt */
    if ((r = fido_assert_set_extensions(assert, FIDO_EXT_HMAC_SECRET)) != FIDO_OK)
        errx(1, "fido_assert_set_extensions: %s (0x%x)", fido_strerr(r), r);
    if ((r = fido_assert_set_hmac_salt(assert, salt, sizeof(salt))) != FIDO_OK)
        errx(1, "fido_assert_set_hmac_salt: %s (0x%x)", fido_strerr(r), r);

    if ((r = fido_dev_get_assert(dev, assert, pin)) != FIDO_OK)
        errx(1, "fido_dev_get_assert: %s (0x%x)", fido_strerr(r), r);

    if (fido_assert_count(assert) != 1)
        errx(1, "unexpected assertion count %zu", fido_assert_count(assert));

    /* Copy the secret */
    if (fido_assert_hmac_secret_ptr(assert, 0) == NULL)
        errx(1, "no hmac-secret returned");

    if ((secret = malloc(32)) == NULL)
        errx(1, "malloc");
    memcpy(secret, fido_assert_hmac_secret_ptr(assert, 0), 32);

    fido_assert_free(&assert);
    fido_dev_close(dev);
    fido_dev_free(&dev);

    return secret;
}

static int
derive_key_hkdf(unsigned char *prf_secret, unsigned char *aes_key)
{
    EVP_PKEY_CTX *pctx;
    unsigned char info[] = "AES-GCM-256-Key-v1";
    size_t outlen = 32;

    if ((pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL)) == NULL)
        return -1;

    if (EVP_PKEY_derive_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(pctx, (const EVP_MD *)EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(pctx, prf_secret, 32) <= 0 ||
        EVP_PKEY_CTX_add1_hkdf_info(pctx, info, sizeof(info) - 1) <= 0 ||
        EVP_PKEY_derive(pctx, aes_key, &outlen) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }

    EVP_PKEY_CTX_free(pctx);
    return 0;
}

static int
prf_encrypt(const char *device_path, const char *cred_id_hex, const char *message, const char *pin)
{
    unsigned char *cred_id, *prf_secret, aes_key[32];
    unsigned char iv[12], tag[16], *ciphertext;
    size_t cred_id_len, message_len, ciphertext_len;
    EVP_CIPHER_CTX *ctx;
    int len;

    /* Decode credential ID */
    cred_id = hex_decode(cred_id_hex, &cred_id_len);

    /* Get PRF secret */
    prf_secret = get_prf_secret(device_path, cred_id, cred_id_len, pin);

    /* Derive AES key using HKDF */
    if (derive_key_hkdf(prf_secret, aes_key) != 0)
        errx(1, "HKDF key derivation failed");

    /* Generate random IV */
    if (RAND_bytes(iv, sizeof(iv)) != 1)
        errx(1, "RAND_bytes failed");

    message_len = strlen(message);
    if ((ciphertext = malloc(message_len)) == NULL)
        errx(1, "malloc");

    /* Encrypt */
    if ((ctx = EVP_CIPHER_CTX_new()) == NULL)
        errx(1, "EVP_CIPHER_CTX_new");

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(iv), NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, aes_key, iv) != 1 ||
        EVP_EncryptUpdate(ctx, ciphertext, &len, (const unsigned char *)message, (int)message_len) != 1 ||
        EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag) != 1)
        errx(1, "encryption failed");

    ciphertext_len = message_len;

    /* Output: IV + ciphertext + tag (all hex encoded) */
    print_hex("", iv, sizeof(iv));
    print_hex("", ciphertext, ciphertext_len);
    print_hex("", tag, sizeof(tag));

    /* Clean up */
    memset(prf_secret, 0, 32);
    memset(aes_key, 0, sizeof(aes_key));
    free(cred_id);
    free(prf_secret);
    free(ciphertext);
    EVP_CIPHER_CTX_free(ctx);

    return 0;
}

static int
prf_decrypt(const char *device_path, const char *cred_id_hex, const char *ciphertext_hex, const char *pin)
{
    unsigned char *cred_id, *prf_secret, aes_key[32];
    unsigned char *combined_data, iv[12], tag[16], *ciphertext, *plaintext;
    size_t cred_id_len, combined_len, ciphertext_len;
    EVP_CIPHER_CTX *ctx;
    int len, plaintext_len;

    /* Decode credential ID and ciphertext */
    cred_id = hex_decode(cred_id_hex, &cred_id_len);
    combined_data = hex_decode(ciphertext_hex, &combined_len);

    /* Extract IV, ciphertext, and tag */
    if (combined_len < sizeof(iv) + sizeof(tag))
        errx(1, "ciphertext too short");

    memcpy(iv, combined_data, sizeof(iv));
    ciphertext_len = combined_len - sizeof(iv) - sizeof(tag);
    ciphertext = combined_data + sizeof(iv);
    memcpy(tag, combined_data + sizeof(iv) + ciphertext_len, sizeof(tag));

    if ((plaintext = malloc(ciphertext_len + 1)) == NULL)
        errx(1, "malloc");

    /* Get PRF secret */
    prf_secret = get_prf_secret(device_path, cred_id, cred_id_len, pin);

    /* Derive AES key using HKDF */
    if (derive_key_hkdf(prf_secret, aes_key) != 0)
        errx(1, "HKDF key derivation failed");

    /* Decrypt */
    if ((ctx = EVP_CIPHER_CTX_new()) == NULL)
        errx(1, "EVP_CIPHER_CTX_new");

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(iv), NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, aes_key, iv) != 1 ||
        EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, (int)ciphertext_len) != 1)
        errx(1, "decryption failed");

    plaintext_len = len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, sizeof(tag), tag) != 1 ||
        EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1)
        errx(1, "authentication failed - wrong key or corrupted data");

    plaintext[plaintext_len] = '\0';
    printf("%s\n", plaintext);

    /* Clean up */
    memset(prf_secret, 0, 32);
    memset(aes_key, 0, sizeof(aes_key));
    free(cred_id);
    free(prf_secret);
    free(combined_data);
    free(plaintext);
    EVP_CIPHER_CTX_free(ctx);

    return 0;
}

static int
prf_make(const char *path, const char *pin)
{
    fido_dev_t *dev;
    fido_cred_t *cred;
    int r;

    if ((dev = fido_dev_new()) == NULL)
        errx(1, "fido_dev_new");
    if ((r = fido_dev_open(dev, path)) != FIDO_OK)
        errx(1, "fido_dev_open: %s (0x%x)", fido_strerr(r), r);

    if ((cred = fido_cred_new()) == NULL)
        errx(1, "fido_cred_new");

    /* Set credential parameters */
    if ((r = fido_cred_set_type(cred, COSE_ES256)) != FIDO_OK)
        errx(1, "fido_cred_set_type: %s (0x%x)", fido_strerr(r), r);
    if ((r = fido_cred_set_clientdata_hash(cred, cdh, sizeof(cdh))) != FIDO_OK)
        errx(1, "fido_cred_set_clientdata_hash: %s (0x%x)", fido_strerr(r), r);
    if ((r = fido_cred_set_rp(cred, "localhost", "localhost")) != FIDO_OK)
        errx(1, "fido_cred_set_rp: %s (0x%x)", fido_strerr(r), r);
    if ((r = fido_cred_set_user(cred, user_id, sizeof(user_id), "john",
        "John Doe", NULL)) != FIDO_OK)
        errx(1, "fido_cred_set_user: %s (0x%x)", fido_strerr(r), r);

    /*
     * Enable the hmac-secret extension. This is the crucial step
     * that instructs the authenticator to generate the necessary
     * internal key material for future PRF operations.
     */
    if ((r = fido_cred_set_extensions(cred, FIDO_EXT_HMAC_SECRET)) != FIDO_OK)
        errx(1, "fido_cred_set_extensions: %s (0x%x)", fido_strerr(r), r);

    if ((r = fido_dev_make_cred(dev, cred, pin)) != FIDO_OK)
        errx(1, "fido_dev_make_cred: %s (0x%x)", fido_strerr(r), r);

    /* Output credential ID and public key */
    print_hex("", fido_cred_id_ptr(cred), fido_cred_id_len(cred));
    print_hex("", fido_cred_pubkey_ptr(cred), fido_cred_pubkey_len(cred));

    fido_cred_free(&cred);
    fido_dev_close(dev);
    fido_dev_free(&dev);

    return 0;
}

int
main(int argc, char **argv)
{
    bool make_cred = false;
    bool encrypt = false;
    bool decrypt = false;
    char *pin = NULL;
    int ch;

    while ((ch = getopt(argc, argv, "MEDP:")) != -1) {
        switch (ch) {
        case 'M':
            make_cred = true;
            break;
        case 'E':
            encrypt = true;
            break;
        case 'D':
            decrypt = true;
            break;
        case 'P':
            pin = optarg;
            break;
        default:
            usage();
        }
    }

    argc -= optind;
    argv += optind;

    if (((int)make_cred + (int)encrypt + (int)decrypt) != 1)
        usage();

    if (make_cred) {
        if (argc != 1)
            usage();
        return prf_make(argv[0], pin);
    } else if (encrypt) {
        if (argc != 3)
            usage();
        return prf_encrypt(argv[0], argv[1], argv[2], pin);
    } else { /* decrypt */
        if (argc != 3)
            usage();
        return prf_decrypt(argv[0], argv[1], argv[2], pin);
    }
}
