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
#include <unistd.h>

#include "fido.h"
#include "compat.h"
#include "extern.h"

static const unsigned char cdh[32] = {
	0xec, 0x8d, 0x8f, 0x78, 0x42, 0x4a, 0x2b, 0xb7,
	0x82, 0x34, 0xaa, 0xca, 0x07, 0xa1, 0xf6, 0x56,
	0x42, 0x1c, 0xb6, 0xf6, 0xb3, 0x00, 0x86, 0x52,
	0x35, 0x2d, 0xa2, 0x62, 0x4a, 0xbe, 0x89, 0x76,
};

static void
usage(void)
{
	fprintf(stderr, "usage: assert [-puv] [-a cred_id] <pubkey> "
	    "<device>\n");
	exit(EXIT_FAILURE);
}

static void
verify_assert(const unsigned char *authdata_ptr, size_t authdata_len,
    const unsigned char *sig_ptr, size_t sig_len, bool up, bool uv,
    const char *key)
{
	fido_assert_t	*assert = NULL;
	EC_KEY		*ec = NULL;
	es256_pk_t	*pk = NULL;
	int		 r;

	/* credential pubkey */
	if ((ec = read_ec_pubkey(key)) == NULL)
		errx(1, "read_ec_pubkey");
	if ((pk = es256_pk_new()) == NULL)
		errx(1, "es256_pk_new");
	if (es256_pk_from_EC_KEY(ec, pk) < 0)
		errx(1, "es256_pk_from_EC_KEY");
	EC_KEY_free(ec);
	ec = NULL;

	/* client data hash */
	if ((assert = fido_assert_new()) == NULL)
		errx(1, "fido_assert_new");
	r = fido_assert_set_clientdata_hash(assert, cdh, sizeof(cdh));
	if (r != FIDO_OK)
		errx(1, "fido_assert_set_clientdata_hash: %s (0x%x)",
		    fido_strerr(r), r);

	/* authdata */
	r = fido_assert_set_count(assert, 1);
	if (r != FIDO_OK)
		errx(1, "fido_assert_set_count: %s (0x%x)", fido_strerr(r), r);
	r = fido_assert_set_authdata(assert, 0, authdata_ptr, authdata_len);
	if (r != FIDO_OK)
		errx(1, "fido_assert_set_authdata: %s (0x%x)", fido_strerr(r), r);

	/* options */
	r = fido_assert_set_options(assert, up, uv);
	if (r != FIDO_OK)
		errx(1, "fido_assert_set_options: %s (0x%x)", fido_strerr(r), r);

	/* sig */
	r = fido_assert_set_sig(assert, 0, sig_ptr, sig_len);
	if (r != FIDO_OK)
		errx(1, "fido_assert_set_sig: %s (0x%x)", fido_strerr(r), r);

	r = fido_assert_verify(assert, 0, pk);
	if (r != FIDO_OK)
		errx(1, "fido_assert_verify: %s (0x%x)", fido_strerr(r), r);

	es256_pk_free(&pk);
	fido_assert_free(&assert);
}

int
main(int argc, char **argv)
{
	bool		 up = false;
	bool		 uv = false;
	bool		 u2f = false;
	fido_dev_t	*dev = NULL;
	fido_assert_t	*assert = NULL;
	unsigned char	*body = NULL;
	size_t		 len;
	int		 ch;
	int		 r;

	if ((assert = fido_assert_new()) == NULL)
		errx(1, "fido_assert_new");

	while ((ch = getopt(argc, argv, "a:puv")) != -1) {
		switch (ch) {
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
		case 'u':
			u2f = true;
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

	if (argc != 2)
		usage();

	fido_init();

	if ((dev = fido_dev_new()) == NULL)
		errx(1, "fido_dev_new");
	r = fido_dev_open(dev, argv[1]);
	if (r != FIDO_OK)
		errx(1, "fido_dev_open");
	if (u2f)
		fido_dev_force_u2f(dev);

	/* client data hash */
	r = fido_assert_set_clientdata_hash(assert, cdh, sizeof(cdh));
	if (r != FIDO_OK)
		errx(1, "fido_assert_set_clientdata_hash: %s (0x%x)",
		    fido_strerr(r), r);

	/* relying party */
	r = fido_assert_set_rp(assert, "localhost");
	if (r != FIDO_OK)
		errx(1, "fido_assert_set_rp: %s (0x%x)", fido_strerr(r), r);

	/* options */
	r = fido_assert_set_options(assert, up, uv);
	if (r != FIDO_OK)
		errx(1, "fido_assert_set_options: %s (0x%x)", fido_strerr(r), r);

	r = fido_dev_get_assert(dev, assert);
	if (r != FIDO_OK)
		errx(1, "fido_dev_get_assert: %s (0x%x)", fido_strerr(r), r);
	r = fido_dev_close(dev);
	if (r != FIDO_OK)
		errx(1, "fido_dev_close: %s (0x%x)", fido_strerr(r), r);

	fido_dev_free(&dev);

	if (fido_assert_count(assert) != 1)
		errx(1, "fido_assert_count: %d signatures returned",
		    (int)fido_assert_count(assert));

	verify_assert(fido_assert_authdata_ptr(assert, 0),
	    fido_assert_authdata_len(assert, 0), fido_assert_sig_ptr(assert, 0),
	    fido_assert_sig_len(assert, 0), up, uv, argv[0]);

	fido_assert_free(&assert);

	exit(0);
}
