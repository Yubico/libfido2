/*
 * Copyright (c) 2026 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "../openbsd-compat/openbsd-compat.h"

#include <fido.h>

/* openssl sha256 -binary </dev/null | xxd -i */
static const unsigned char CLIENT_DATA_HASH[] = {
	0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
	0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
	0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
	0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
};

#define RPID      "relying party"
#define USER_NAME "Archimedes"

static const unsigned char USER_ID[] = {
	0x33, 0x2e, 0x31, 0x34, 0x31, 0x35, 0x39, 0x32,
	0x36, 0x35, 0x33, 0x35, 0x38, 0x39, 0x37, 0x39,
	0x33, 0x32, 0x33, 0x38, 0x34, 0x36, 0x32, 0x36,
	0x34, 0x33, 0x33
};

static const unsigned char LARGE_BLOB[] = {
	0x49, 0x6e, 0x20, 0x41, 0x6e, 0x63, 0x69, 0x65,
	0x6e, 0x74, 0x20, 0x47, 0x72, 0x65, 0x65, 0x6b,
	0x20, 0x6f, 0x6e, 0x65, 0x20, 0x63, 0x6f, 0x75,
	0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x6d, 0x61,
	0x74, 0x68, 0x65, 0x6d, 0x61, 0x74, 0x69, 0x63,
	0x69, 0x61, 0x6e, 0x2c, 0x20, 0x70, 0x68, 0x79,
	0x73, 0x69, 0x63, 0x69, 0x73, 0x74, 0x2c, 0x20,
	0x65, 0x6e, 0x67, 0x69, 0x6e, 0x65, 0x65, 0x72,
	0x20, 0x61, 0x73, 0x74, 0x72, 0x6f, 0x6e, 0x6f,
	0x6d, 0x65, 0x72, 0x2c, 0x20, 0x61, 0x6e, 0x64,
	0x20, 0x69, 0x6e, 0x76, 0x65, 0x6e, 0x74, 0x6f,
	0x72, 0x20, 0x61, 0x74, 0x20, 0x74, 0x68, 0x65,
	0x20, 0x73, 0x61, 0x6d, 0x65, 0x20, 0x74, 0x69,
	0x6d, 0x65, 0x0a
};

static int
prepare_cred(fido_cred_t **cred_out)
{
	int r;
	fido_cred_t *cred = NULL;

	if ((cred = fido_cred_new()) == NULL)
		errx(1, "fido_cred_new");

	if ((r = fido_cred_set_clientdata_hash(cred, CLIENT_DATA_HASH,
	    sizeof(CLIENT_DATA_HASH))) != FIDO_OK) {
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

	if ((r = fido_cred_set_user(cred, USER_ID, sizeof(USER_ID), USER_NAME,
	    NULL, NULL)) != FIDO_OK) {
		warnx("fido_cred_set_user: %s", fido_strerr(r));
		goto exit;
	}

	if ((r = fido_cred_set_rk(cred, FIDO_OPT_TRUE)) != FIDO_OK) {
		warnx("fido_cred_set_rk: %s", fido_strerr(r));
		goto exit;
	}

	if ((r = fido_cred_set_extensions(cred,
	    FIDO_EXT_LARGEBLOB_KEY)) != FIDO_OK) {
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
run_make_cred(fido_dev_t *dev, const char *pin)
{
	int 		 r;
	fido_cred_t 	*cred = NULL;

	warnx("Create PUAT");
	if ((r = fido_dev_get_puat(dev,
	    FIDO_PUAT_MAKECRED | FIDO_PUAT_LARGEBLOB, RPID, pin)) != FIDO_OK) {
		warnx("could not get puat: %s", fido_strerr(r));
		return r;
	}

	warnx("Make credential");
	if ((r = prepare_cred(&cred)) != FIDO_OK)
		return r;
	if ((r = fido_dev_make_cred(dev, cred, NULL)) != FIDO_OK) {
		warnx("could not make cred: %s", fido_strerr(r));
		goto exit;
	}

	warnx("Add large blob (%zu bytes)", sizeof(LARGE_BLOB));
	if ((r = fido_dev_largeblob_set(dev, fido_cred_largeblob_key_ptr(cred),
	    fido_cred_largeblob_key_len(cred), LARGE_BLOB, sizeof(LARGE_BLOB),
	    NULL)) != FIDO_OK)
		warnx("fido_dev_largeblob_set: %s", fido_strerr(r));

exit:
	fido_cred_free(&cred);
	return r;
}

static int
prepare_assert(fido_assert_t **assert_out)
{
	int r;
	fido_assert_t *assert;

	if ((assert = fido_assert_new()) == NULL)
		errx(1, "fido_assert_new");

	if ((r = fido_assert_set_clientdata_hash(assert, CLIENT_DATA_HASH,
	    sizeof(CLIENT_DATA_HASH))) != FIDO_OK) {
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

	if ((r = fido_assert_set_extensions(assert,
	    FIDO_EXT_LARGEBLOB_KEY)) != FIDO_OK) {
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
run_get_assertion(fido_dev_t *dev, const char *pin)
{
	fido_assert_t	*assert;
	unsigned char 	*blob_ptr = NULL;
	size_t 		 n_assert, blob_len = 0;
	int 		 r;

	warnx("Create PUAT");
	if ((r = fido_dev_get_puat(dev,
	    FIDO_PUAT_GETASSERT | FIDO_PUAT_LARGEBLOB, RPID,
	    pin)) != FIDO_OK) {
		warnx("could not get puat: %s", fido_strerr(r));
		return r;
	}

	warnx("Get Assert");
	if ((r = prepare_assert(&assert)) != FIDO_OK)
		goto exit;
	if ((r = fido_dev_get_assert(dev, assert, NULL)) != FIDO_OK) {
		warnx("fido_dev_get_assert: %s", fido_strerr(r));
		goto exit;
	}

	if ((n_assert = fido_assert_count(assert)) != 1) {
		warnx("fido_assert_count -> %zu", n_assert);
		if (n_assert == 0)
			goto exit;
	}

	warnx("Extract large blob");
	if ((r = fido_dev_largeblob_get(dev,
	    fido_assert_largeblob_key_ptr(assert, 0),
	    fido_assert_largeblob_key_len(assert, 0),
	    &blob_ptr, &blob_len)) != FIDO_OK) {
		warnx("fido_dev_largeblob_get: %s", fido_strerr(r));
		goto exit;
	}

	warnx("Remove large blob (%zu bytes)", blob_len);
	if ((r = fido_dev_largeblob_remove(dev,
	    fido_assert_largeblob_key_ptr(assert, 0),
	    fido_assert_largeblob_key_len(assert, 0),
	    NULL)) != FIDO_OK)
		warnx("fido_dev_largeblob_remove: %s", fido_strerr(r));

	r = 0;
exit:
	free(blob_ptr);
	fido_assert_free(&assert);
	return r;
}

static void
usage(void)
{
	fprintf(stderr, "usage: largeblob [-P pin] <device>\n");
	exit(1);
}

int
main(int argc, char **argv)
{
	fido_dev_t	*dev = NULL;
	int		 r, ch;
	const char	*path, *pin = NULL;

	while ((ch = getopt(argc, argv, "P:")) != -1) {
		switch (ch) {
		case 'P':
			pin = optarg;
			break;
		default:
			usage();
		}
	}

	if (argc - optind < 1)
		usage();
	path = argv[optind];

	fido_init(0);

	if ((dev = fido_dev_new()) == NULL)
		errx(1, "fido_dev_new");

	if ((r = fido_dev_open(dev, path)) != FIDO_OK) {
		warnx("could not open %s: %s", path, fido_strerr(r));
		goto quit;
	}

	warnx("Make credential + large blob");
	if ((r = run_make_cred(dev, pin)) != FIDO_OK)
		goto quit;

	warnx("Get assertion + large blob");
	r = run_get_assertion(dev, pin);

quit:
	fido_dev_close(dev);
	fido_dev_free(&dev);
	return r ? 1 : 0;
}
