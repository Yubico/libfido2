/*
 * Copyright (c) 2022 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <assert.h>
#include <err.h>

#include <fido.h>
#include <fido/es256.h>
#include <openssl/pem.h>

static char short_pk_x[] = \
"-----BEGIN PUBLIC KEY-----\n"
"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAAeeHTZj4LEbt7Czs+u5gEZJfnGE\n"
"6Z+YLe4AYu7SoGY7IH/2jKifsA7w+lkURL4DL63oEjd3f8foH9bX4eaVug==\n"
"-----END PUBLIC KEY-----";

static char short_pk_y[] = \
"-----BEGIN PUBLIC KEY-----\n"
"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEL8CWUP1r0tpJ5QmkzLc69O74C/Ti\n"
"83hTiys/JFNVkp0ArW3pKt5jNRrgWSZYE4S/D3AMtpqifFXz/FLCzJqojQ==\n"
"-----END PUBLIC KEY-----\n";

static int
es256_pk_cmp(char *ptr, size_t len)
{
	FILE *f = NULL;
	EVP_PKEY *pkA = NULL;
	EVP_PKEY *pkB = NULL;
	es256_pk_t *k = NULL;
	int r, ok = -1;

	if ((f = fmemopen(ptr, len, "r")) == NULL) {
		warn("fmemopen");
		goto out;
	}
	if ((pkA = PEM_read_PUBKEY(f, NULL, NULL, NULL)) == NULL) {
		warnx("PEM_read_PUBKEY");
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
	if (f != NULL)
		fclose(f);

	EVP_PKEY_free(pkA);
	EVP_PKEY_free(pkB);
	es256_pk_free(&k);

	return ok;
}

int
main(void)
{
	fido_init(0);

	assert(es256_pk_cmp(short_pk_x, sizeof(short_pk_x)) == 0);
	assert(es256_pk_cmp(short_pk_y, sizeof(short_pk_y)) == 0);

	exit(0);
}
