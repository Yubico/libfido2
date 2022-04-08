/*
 * Copyright (c) 2022 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <assert.h>
#include <err.h>

#include <fido.h>
#include <fido/es256.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

#define ASSERT_NOT_NULL(e)	assert((e) != NULL)
#define ASSERT_NULL(e)		assert((e) == NULL)
#define ASSERT_INVAL(e)		assert((e) == FIDO_ERR_INVALID_ARGUMENT)

static char short_x[] = \
"-----BEGIN PUBLIC KEY-----\n"
"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAAeeHTZj4LEbt7Czs+u5gEZJfnGE\n"
"6Z+YLe4AYu7SoGY7IH/2jKifsA7w+lkURL4DL63oEjd3f8foH9bX4eaVug==\n"
"-----END PUBLIC KEY-----";

static char short_y[] = \
"-----BEGIN PUBLIC KEY-----\n"
"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEL8CWUP1r0tpJ5QmkzLc69O74C/Ti\n"
"83hTiys/JFNVkp0ArW3pKt5jNRrgWSZYE4S/D3AMtpqifFXz/FLCzJqojQ==\n"
"-----END PUBLIC KEY-----\n";

static char p256k1[] = \
"-----BEGIN PUBLIC KEY-----\n"
"MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEU1y8c0Jg9FGr3vYChpEo9c4dpkijriYM\n"
"QzU/DeskC89hZjLNH1Sj8ra2MsBlVGGJTNPCZSyx8Jo7ERapxdN7UQ==\n"
"-----END PUBLIC KEY-----\n";

static const unsigned char p256k1_raw[] = {
	0x53, 0x5c, 0xbc, 0x73, 0x42, 0x60, 0xf4, 0x51,
	0xab, 0xde, 0xf6, 0x02, 0x86, 0x91, 0x28, 0xf5,
	0xce, 0x1d, 0xa6, 0x48, 0xa3, 0xae, 0x26, 0x0c,
	0x43, 0x35, 0x3f, 0x0d, 0xeb, 0x24, 0x0b, 0xcf,
	0x61, 0x66, 0x32, 0xcd, 0x1f, 0x54, 0xa3, 0xf2,
	0xb6, 0xb6, 0x32, 0xc0, 0x65, 0x54, 0x61, 0x89,
	0x4c, 0xd3, 0xc2, 0x65, 0x2c, 0xb1, 0xf0, 0x9a,
	0x3b, 0x11, 0x16, 0xa9, 0xc5, 0xd3, 0x7b, 0x51,
};

static EVP_PKEY *
EVP_PKEY_from_PEM(char *ptr, size_t len)
{
	BIO *bio = NULL;
	EVP_PKEY *pkey = NULL;

	if ((bio = BIO_new(BIO_s_mem())) == NULL) {
		warnx("BIO_new");
		goto out;
	}
	if (len > INT_MAX || BIO_write(bio, ptr, (int)len) != (int)len) {
		warnx("BIO_write");
		goto out;
	}
	if ((pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL)) == NULL)
		warnx("PEM_read_bio_PUBKEY");
out:
	BIO_free(bio);

	return pkey;
}

static int
es256_pk_cmp(char *ptr, size_t len)
{
	EVP_PKEY *pkA = NULL;
	EVP_PKEY *pkB = NULL;
	es256_pk_t *k = NULL;
	int r, ok = -1;

	if ((pkA = EVP_PKEY_from_PEM(ptr, len)) == NULL) {
		warnx("EVP_PKEY_from_PEM");
		goto out;
	}
	if ((k = es256_pk_new()) == NULL) {
		warnx("es256_pk_new");
		goto out;
	}
	if ((r = es256_pk_from_EVP_PKEY(k, pkA)) != FIDO_OK) {
		warnx("es256_pk_from_EVP_PKEY: 0x%x", r);
		goto out;
	}
	if ((pkB = es256_pk_to_EVP_PKEY(k)) == NULL) {
		warnx("es256_pk_to_EVP_PKEY");
		goto out;
	}
	if ((r = EVP_PKEY_cmp(pkA, pkB)) != 1) {
		warnx("EVP_PKEY_cmp: %d", r);
		goto out;
	}

	ok = 0;
out:
	EVP_PKEY_free(pkA);
	EVP_PKEY_free(pkB);
	es256_pk_free(&k);

	return ok;
}

static void
short_coord(void)
{
	assert(es256_pk_cmp(short_x, sizeof(short_x)) == 0);
	assert(es256_pk_cmp(short_y, sizeof(short_y)) == 0);
}

static void
invalid_curve(void)
{
	EVP_PKEY *pkey;
	es256_pk_t *pk;

	ASSERT_NOT_NULL((pkey = EVP_PKEY_from_PEM(p256k1, sizeof(p256k1))));
	ASSERT_NOT_NULL((pk = es256_pk_new()));
	ASSERT_INVAL(es256_pk_from_EVP_PKEY(pk, pkey));
	ASSERT_INVAL(es256_pk_from_ptr(pk, p256k1_raw, sizeof(p256k1_raw)));
	ASSERT_NULL(es256_pk_to_EVP_PKEY((const es256_pk_t *)p256k1_raw));

	EVP_PKEY_free(pkey);
	es256_pk_free(&pk);
}

int
main(void)
{
	fido_init(0);

	short_coord();
	invalid_curve();

	exit(0);
}
