/*
 * Copyright (c) 2026 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <err.h>
#include <sysexits.h>

#include <fido.h>

/* openssl sha256 -binary </dev/null | xxd -i */
static const unsigned char CLIENT_DATA_HASH[] = {
	0xe3, 0xb0, 0xc4, 0x42,
	0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9,
	0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95,
	0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
};

#define RPID      "relying party"
#define USER_NAME "Archimedes"

static const unsigned char USER_ID[] = {
	0x33, 0x2e, 0x31, 0x34, 0x31, 0x35,
	0x39, 0x32, 0x36, 0x35, 0x33, 0x35, 0x38, 0x39, 0x37, 0x39, 0x33,
	0x32, 0x33, 0x38, 0x34, 0x36, 0x32, 0x36, 0x34, 0x33, 0x33
};

static const unsigned char LARGE_BLOB[] = {
	0x49, 0x6e, 0x20, 0x41, 0x6e,
	0x63, 0x69, 0x65, 0x6e, 0x74, 0x20, 0x47, 0x72, 0x65, 0x65, 0x6b,
	0x20, 0x6f, 0x6e, 0x65, 0x20, 0x63, 0x6f, 0x75, 0x6c, 0x64, 0x20,
	0x62, 0x65, 0x20, 0x6d, 0x61, 0x74, 0x68, 0x65, 0x6d, 0x61, 0x74,
	0x69, 0x63, 0x69, 0x61, 0x6e, 0x2c, 0x20, 0x70, 0x68, 0x79, 0x73,
	0x69, 0x63, 0x69, 0x73, 0x74, 0x2c, 0x20, 0x65, 0x6e, 0x67, 0x69,
	0x6e, 0x65, 0x65, 0x72, 0x20, 0x61, 0x73, 0x74, 0x72, 0x6f, 0x6e,
	0x6f, 0x6d, 0x65, 0x72, 0x2c, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x69,
	0x6e, 0x76, 0x65, 0x6e, 0x74, 0x6f, 0x72, 0x20, 0x61, 0x74, 0x20,
	0x74, 0x68, 0x65, 0x20, 0x73, 0x61, 0x6d, 0x65, 0x20, 0x74, 0x69,
	0x6d, 0x65, 0x0a
};

static int
prepare_cred(fido_cred_t **cred_out)
{
	int r;
	fido_cred_t *cred = NULL;

	if ((cred = fido_cred_new()) == NULL)
		errx(EX_OSERR, "fido_cred_new");

	r = fido_cred_set_clientdata_hash(cred, CLIENT_DATA_HASH,
	    sizeof(CLIENT_DATA_HASH));
	if (r != FIDO_OK) {
		warnx("fido_cred_set_clientdata_hash: %s", fido_strerr(r));
		goto exit;
	}

	if ((r = fido_cred_set_type(cred, COSE_ES256)) != FIDO_OK) {
		warnx("fido_cred_set_type: %s", fido_strerr(r));
		goto exit;
	}

	if ((r = fido_cred_set_rp(cred, RPID, NULL)) != FIDO_OK) {
		warnx("fido_cred_set_rp: %s", fido_strerr(r));
		goto exit;
	}

	r = fido_cred_set_user(cred, USER_ID, sizeof(USER_ID), USER_NAME, NULL,
	    NULL);
	if (r != FIDO_OK) {
		warnx("fido_cred_set_user: %s", fido_strerr(r));
		goto exit;
	}

	if ((r = fido_cred_set_rk(cred, FIDO_OPT_TRUE)) != FIDO_OK) {
		warnx("fido_cred_set_rk: %s", fido_strerr(r));
		goto exit;
	}

	if ((r = fido_cred_set_extensions(cred, FIDO_EXT_LARGEBLOB_KEY)) !=
	    FIDO_OK) {
		warnx("fido_cred_set_extensions: %s", fido_strerr(r));
		goto exit;
	}

exit:
	if (r)
		fido_cred_free(&cred);
	else
		*cred_out = cred;
	return r;
}

static int
blob_cmp(const unsigned char *p1, size_t s1, const unsigned char *p2,
    size_t s2)
{
	if (s1 < s2)
		return -1;
	if (s2 < s1)
		return 1;
	return memcmp(p1, p2, s1);
}

static int
set_large_blob(fido_dev_t *dev, fido_cred_t *cred)
{
	int r;

	r = fido_dev_largeblob_set(dev, fido_cred_largeblob_key_ptr(cred),
	    fido_cred_largeblob_key_len(cred), LARGE_BLOB, sizeof(LARGE_BLOB),
	    NULL);

	if (r != FIDO_OK)
		warnx("fido_dev_largeblob_set: %s", fido_strerr(r));

	return r;
}

static int
run_make_cred(fido_dev_t *dev)
{
	int r;
	fido_cred_t *cred = NULL;

	if ((r = prepare_cred(&cred)) != FIDO_OK)
		return r;

	warnx("Creating credential");
	if ((r = fido_dev_make_cred(dev, cred, NULL)) != FIDO_OK) {
		warnx("could not make cred: %s", fido_strerr(r));
		goto exit;
	}

	warnx("Add large blob");
	if ((r = set_large_blob(dev, cred)) != FIDO_OK)
		goto exit;

	r = 0;
exit:
	fido_cred_free(&cred);
	return r;
}

static int
check_large_blob(fido_dev_t *dev, fido_assert_t *assert)
{
	int r = -1;
	unsigned char *blob_ptr = NULL;
	size_t n_assert, blob_len = 0;

	n_assert = fido_assert_count(assert);
	if (n_assert != 1) {
		warnx("fido_assert_count -> %zu", n_assert);
		if (n_assert == 0)
			goto exit;
	}

	r = fido_dev_largeblob_get(dev,
	    fido_assert_largeblob_key_ptr(assert, 0),
	    fido_assert_largeblob_key_len(assert, 0), &blob_ptr, &blob_len);

	if (r != FIDO_OK) {
		warnx("fido_dev_largeblob_get: %s", fido_strerr(r));
		goto exit;
	}

	/* Consistency check, perhaps outside the scope of this example. */
	if (blob_cmp(LARGE_BLOB, sizeof(LARGE_BLOB), blob_ptr, blob_len)) {
		warnx("unexpectedly different blobs");
		goto exit;
	}

	r = 0;
exit:
	free(blob_ptr);
	return r;
}

static int
prepare_assert(fido_assert_t **assert_out)
{
	int r;
	fido_assert_t *assert;

	if ((assert = fido_assert_new()) == NULL)
		err(EX_OSERR, "fido_assert_new");

	if ((r = fido_assert_set_clientdata_hash(assert, CLIENT_DATA_HASH,
	    sizeof(CLIENT_DATA_HASH))) !=
	    FIDO_OK) {
		warnx("fido_assert_set_clientdata_hash: %s", fido_strerr(r));
		goto fail;
	}

	if ((r = fido_assert_set_up(assert, FIDO_OPT_FALSE)) != FIDO_OK) {
		warnx("fido_assert_set_up: %s", fido_strerr(r));
		goto fail;
	}

	if ((r = fido_assert_set_rp(assert, RPID)) != FIDO_OK) {
		warnx("fido_assert_set_rp: %s", fido_strerr(r));
		goto fail;
	}

	if ((r = fido_assert_set_extensions(assert, FIDO_EXT_LARGEBLOB_KEY)) !=
	    FIDO_OK) {
		warnx("fido_assert_set_extensions: %s", fido_strerr(r));
		goto fail;
	}

	*assert_out = assert;
	return 0;
fail:
	fido_assert_free(&assert);
	return r;
}

static int
run_get_assertion(fido_dev_t *dev)
{
	fido_assert_t *assert;
	int r;

	r = prepare_assert(&assert);
	if (r)
		goto exit;

	warnx("Get Assert");
	if ((r = fido_dev_get_assert(dev, assert, NULL)) != FIDO_OK) {
		warnx("fido_dev_get_assert: %s", fido_strerr(r));
		goto exit;
	}

	warnx("Extract large blob");
	r = check_large_blob(dev, assert);
exit:
	fido_assert_free(&assert);
	return r;
}

static int
run(fido_dev_t *dev, const char *pin)
{
	int r;

	warnx("Make credential + large blob");
	r = fido_dev_get_puat(dev,
	    CTAP21_UV_TOKEN_PERM_MAKECRED | CTAP21_UV_TOKEN_PERM_LARGEBLOB,
	    RPID, pin);
	if (r) {
		warnx("could not get puat: %s", fido_strerr(r));
		return r;
	}
	r = run_make_cred(dev);
	if (r)
		return r;

	warnx("Get assertion + large blob");
	r = fido_dev_get_puat(dev,
	    CTAP21_UV_TOKEN_PERM_ASSERT | CTAP21_UV_TOKEN_PERM_LARGEBLOB, RPID,
	    pin);
	if (r) {
		warnx("could not get puat: %s", fido_strerr(r));
		return r;
	}
	return run_get_assertion(dev);
}

static void
usage(int argc, char **argv)
{
	fprintf(stderr, "usage: %s <pin> <dev>\n",
	    (argc > 0 && argv[0] != NULL) ? argv[0] : "puat-mgca");

	exit(1);
}

int
main(int argc, char **argv)
{
	fido_dev_t *dev = NULL;
	int r = 1;
	const char *path, *pin;

	if (argc < 3)
		usage(argc, argv);
	pin = argv[1];
	path = argv[2];

	fido_init(0);

	if ((dev = fido_dev_new()) == NULL)
		return 1;

	r = fido_dev_open(dev, path);
	if (r) {
		warnx("could not open %s: %s", path, fido_strerr(r));
		goto quit;
	}

	r = run(dev, pin);
quit:
	fido_dev_close(dev);
	fido_dev_free(&dev);
	return r ? 1 : 0;
}
