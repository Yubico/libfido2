/*
 * Copyright (c) 2018 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <openssl/ec.h>

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "fido.h"
#include "extern.h"
#include "../openbsd-compat/openbsd-compat.h"

static const unsigned char cdh[32] = {
	0xec, 0x8d, 0x8f, 0x78, 0x42, 0x4a, 0x2b, 0xb7,
	0x82, 0x34, 0xaa, 0xca, 0x07, 0xa1, 0xf6, 0x56,
	0x42, 0x1c, 0xb6, 0xf6, 0xb3, 0x00, 0x86, 0x52,
	0x35, 0x2d, 0xa2, 0x62, 0x4a, 0xbe, 0x89, 0x76,
};

static const unsigned char blob_write[128] = {
	0x21, 0x34, 0x17, 0xd7, 0x1c, 0x70, 0x5b, 0xf3,
	0xea, 0x4e, 0x46, 0xb7, 0x9c, 0xb5, 0x74, 0x28,
	0xd6, 0xcd, 0xfb, 0x18, 0x49, 0x20, 0x64, 0xdc,
	0xe8, 0x14, 0x15, 0x96, 0x81, 0x9f, 0xd7, 0x22,
	0x92, 0xe9, 0x5e, 0x39, 0x79, 0xc3, 0xae, 0xba,
	0x20, 0xd2, 0x67, 0x51, 0xd4, 0x2d, 0x07, 0x9d,
	0xd7, 0x8b, 0x20, 0xd2, 0x1f, 0x95, 0xb9, 0xcf,
	0x18, 0xb9, 0x28, 0x76, 0x47, 0x50, 0x9f, 0x44,
	0x95, 0xff, 0xe9, 0x75, 0x84, 0xe7, 0xb4, 0x2a,
	0xf9, 0xd6, 0xec, 0x98, 0x7e, 0xd7, 0x85, 0xb1,
	0x74, 0xf1, 0xcd, 0x58, 0x61, 0x3d, 0xa9, 0xdd,
	0x90, 0xf7, 0x6d, 0x76, 0x20, 0x4a, 0x9a, 0x9c,
	0x47, 0xd4, 0xb6, 0x0c, 0xf1, 0x5d, 0x47, 0xcd,
	0xb1, 0x6e, 0x6b, 0x5f, 0xc0, 0x32, 0xf4, 0x93,
	0xbe, 0x80, 0x8f, 0xd5, 0xa7, 0xda, 0xe8, 0x63,
	0xfb, 0xc1, 0x6b, 0x07, 0xa3, 0x8a, 0x42, 0xd9, 
};

static void
usage(void)
{
	fprintf(stderr, "usage: largeblob [-a cred_id] "
	    "[-s hmac_salt] [-P pin] [-pv] <pubkey>\n");
	exit(EXIT_FAILURE);
}

static void
verify_blob(fido_blob_t *blob)
{
	if (blob == NULL || fido_blob_ptr(blob) == NULL ||
	    fido_blob_len(blob) != sizeof(blob_write))
		errx(1, "%s: blob=%p, size=%zu", __func__,
		    (const void *)fido_blob_ptr(blob), fido_blob_len(blob));

	if (memcmp(fido_blob_ptr(blob), blob_write, sizeof(blob_write)) != 0)
		errx(1, "%s: memcmp", __func__);
}

static int
get_assertion(fido_dev_t *dev, fido_assert_t *assert, bool up, bool uv,
    int ext, const char *pin)
{
	int r;

	/* client data hash */
	r = fido_assert_set_clientdata_hash(assert, cdh, sizeof(cdh));
	if (r != FIDO_OK)
		errx(1, "fido_assert_set_clientdata_hash: %s (0x%x)",
		    fido_strerr(r), r);

	/* relying party */
	r = fido_assert_set_rp(assert, "localhost");
	if (r != FIDO_OK)
		errx(1, "fido_assert_set_rp: %s (0x%x)", fido_strerr(r), r);

	/* extensions */
	r = fido_assert_set_extensions(assert, ext);
	if (r != FIDO_OK)
		errx(1, "fido_assert_set_extensions: %s (0x%x)", fido_strerr(r), r);

	/* user presence */
	if (up && (r = fido_assert_set_up(assert, FIDO_OPT_TRUE)) != FIDO_OK)
		errx(1, "fido_assert_set_up: %s (0x%x)", fido_strerr(r), r);

	/* user verification */
	if (uv && (r = fido_assert_set_uv(assert, FIDO_OPT_TRUE)) != FIDO_OK)
		errx(1, "fido_assert_set_uv: %s (0x%x)", fido_strerr(r), r);

	r = fido_dev_get_assert(dev, assert, pin);
	if (r != FIDO_OK)
		errx(1, "fido_dev_get_assert: %s (0x%x)", fido_strerr(r), r);

	return (r);
}

int
main(int argc, char **argv)
{
	bool		 up = false;
	bool		 uv = false;
	fido_dev_t	*dev = NULL;
	fido_assert_t	*assert = NULL;
	const char	*pin = NULL;
	unsigned char	*body = NULL;
	fido_blob_t	*blob = NULL;
	size_t		 len;
	int		 ext = FIDO_EXT_LARGEBLOB_KEY;
	int		 ch;
	int		 r;

	if ((assert = fido_assert_new()) == NULL)
		errx(1, "fido_assert_new");

	while ((ch = getopt(argc, argv, "P:a:ps:v")) != -1) {
		switch (ch) {
		case 'P':
			pin = optarg;
			break;
		case 'a':
			if (read_blob(optarg, &body, &len) < 0)
				errx(1, "read_blob: %s", optarg);
			if ((r = fido_assert_allow_cred(assert, body,
			    len)) != FIDO_OK)
				errx(1, "fido_assert_allow_cred: %s (0x%x)",
				    fido_strerr(r), r);
			free(body);
			body = NULL;
			break;
		case 'p':
			up = true;
			break;
		case 's':
			ext |= FIDO_EXT_HMAC_SECRET;
			if (read_blob(optarg, &body, &len) < 0)
				errx(1, "read_blob: %s", optarg);
			if ((r = fido_assert_set_hmac_salt(assert, body,
			    len)) != FIDO_OK)
				errx(1, "fido_assert_set_hmac_salt: %s (0x%x)",
				    fido_strerr(r), r);
			free(body);
			body = NULL;
			break;
		case 'v':
			uv = true;
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 1)
		usage();

	fido_init(0);

	if ((dev = fido_dev_new()) == NULL)
		errx(1, "fido_dev_new");

	r = fido_dev_open(dev, argv[0]);
	if (r != FIDO_OK)
		errx(1, "fido_dev_open: %s (0x%x)", fido_strerr(r), r);

	r = get_assertion(dev, assert, up, uv, ext, pin);
	if (r != FIDO_OK)
		errx(1, "get_assertion: %s (0x%x)", fido_strerr(r), r);

	if ((blob = fido_blob_new()) == NULL)
		errx(1, "fido_blob_new");

	r = fido_blob_set(blob, blob_write, sizeof(blob_write));
	if (r != FIDO_OK)
		errx(1, "fido_blob_set");

	r = fido_dev_largeblob_put(dev, fido_assert_largeblob_key_ptr(assert, 0),
		fido_assert_largeblob_key_len(assert, 0), blob, pin);
	if (r != FIDO_OK)
		errx(1, "fido_dev_largeblob_put: %s (0x%x)", fido_strerr(r), r);

	r = fido_dev_largeblob_get(dev, fido_assert_largeblob_key_ptr(assert, 0),
	    fido_assert_largeblob_key_len(assert, 0), blob);
	if (r != FIDO_OK)
		errx(1, "fido_dev_largeblob_get 1: %s (0x%x)", fido_strerr(r), r);

	/* blob should be identical to what we just wrote */
	verify_blob(blob);

	r = fido_dev_largeblob_remove(dev, fido_assert_largeblob_key_ptr(assert, 0),
	    fido_assert_largeblob_key_len(assert, 0), pin);
	if (r != FIDO_OK)
		errx(1, "fido_dev_largeblob_remove: %s (0x%x)", fido_strerr(r), r);

	/* there should no longer be a blob for this key */
	r = fido_dev_largeblob_get(dev, fido_assert_largeblob_key_ptr(assert, 0),
	    fido_assert_largeblob_key_len(assert, 0), blob);
	if (r != FIDO_ERR_NOTFOUND)
		errx(1, "fido_dev_largeblob_get 2: %s (0x%x)", fido_strerr(r), r);

	r = fido_dev_close(dev);
	if (r != FIDO_OK)
		errx(1, "fido_dev_close: %s (0x%x)", fido_strerr(r), r);

	fido_blob_free(&blob);
	fido_dev_free(&dev);
	fido_assert_free(&assert);

	exit(0);
}
