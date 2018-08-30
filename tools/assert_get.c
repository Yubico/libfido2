/*
 * Copyright (c) 2018 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <fido.h>

#include "../openbsd-compat/openbsd-compat.h"
#include "extern.h"

static fido_assert_t *
prepare_assert(FILE *in_f, bool rk, bool up, bool uv, bool debug)
{
	fido_assert_t *assert = NULL;
	struct blob cdh;
	struct blob id;
	char *rpid = NULL;
	int r;

	memset(&cdh, 0, sizeof(cdh));
	memset(&id, 0, sizeof(id));

	r = base64_read(in_f, &cdh);
	r |= string_read(in_f, &rpid);
	if (rk == false)
		r |= base64_read(in_f, &id);
	if (r < 0)
		errx(1, "input error");

	if (debug) {
		fprintf(stderr, "client data hash:\n");
		xxd(cdh.ptr, cdh.len);
		fprintf(stderr, "relying party id: %s\n", rpid);
		if (rk == false) {
			fprintf(stderr, "credential id:\n");
			xxd(id.ptr, id.len);
		}
	}

	if ((assert = fido_assert_new()) == NULL)
		errx(1, "fido_assert_new");

	if ((r = fido_assert_set_clientdata_hash(assert, cdh.ptr,
	    cdh.len)) != FIDO_OK ||
	    (r = fido_assert_set_rp(assert, rpid)) != FIDO_OK ||
	    (r = fido_assert_set_options(assert, up, uv)) != FIDO_OK)
		errx(1, "fido_assert_set: %s", fido_strerr(r));

	if (rk == false && (r = fido_assert_allow_cred(assert, id.ptr,
	    id.len)) != FIDO_OK)
		errx(1, "fido_assert_allow_cred: %s", fido_strerr(r));

	free(cdh.ptr);
	free(id.ptr);
	free(rpid);

	return (assert);
}

static void
print_assert(FILE *out_f, const fido_assert_t *assert)
{
	char *cdh = NULL;
	char *authdata = NULL;
	char *sig = NULL;
	int r;

	r = base64_encode(fido_assert_clientdata_hash_ptr(assert),
	    fido_assert_clientdata_hash_len(assert), &cdh);
	r |= base64_encode(fido_assert_authdata_ptr(assert, 0),
	    fido_assert_authdata_len(assert, 0), &authdata);
	r |= base64_encode(fido_assert_sig_ptr(assert, 0),
	    fido_assert_sig_len(assert, 0), &sig);
	if (r < 0)
		errx(1, "output error");

	fprintf(out_f, "%s\n", cdh);
	fprintf(out_f, "%s\n", fido_assert_rp_id(assert));
	fprintf(out_f, "%s\n", authdata);
	fprintf(out_f, "%s\n", sig);

	free(cdh);
	free(authdata);
	free(sig);
}

int
assert_get(int argc, char **argv)
{
	fido_dev_t *dev = NULL;
	fido_assert_t *assert = NULL;
	char pin[1024];
	char prompt[1024];
	FILE *in_f = stdin;
	FILE *out_f = stdout;
	bool rk = false;
	bool up = false;
	bool uv = false;
	bool debug = false;
	int ch;
	int r;

	while ((ch = getopt(argc, argv, "di:o:prv")) != -1) {
		switch (ch) {
		case 'd':
			debug = true;
			break;
		case 'i':
			if (strcmp(optarg, "-"))
				in_f = open_read(optarg);
			break;
		case 'o':
			if (strcmp(optarg, "-"))
				out_f = open_write(optarg);
			break;
		case 'p':
			up = true;
			break;
		case 'r':
			rk = true;
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

	fido_init(debug ? FIDO_DEBUG : 0);
	dev = open_dev(argv[0]);
	assert= prepare_assert(in_f, rk, up, uv, debug);

	if (uv) {
		r = snprintf(prompt, sizeof(prompt), "Enter PIN for %s: ",
		    argv[0]);
		if (r < 0 || (size_t)r >= sizeof(prompt))
			errx(1, "snprintf");
		if (!readpassphrase(prompt, pin, sizeof(pin), RPP_ECHO_OFF))
			errx(1, "readpassphrase");
		r = fido_dev_get_assert(dev, assert, pin);
	} else
		r = fido_dev_get_assert(dev, assert, NULL);

	explicit_bzero(pin, sizeof(pin));

	if (r != FIDO_OK)
		errx(1, "fido_dev_get_assert: %s", fido_strerr(r));

	if (fido_assert_count(assert) != 1)
		errx(1, "fido_assert_count: %zu", fido_assert_count(assert));

	print_assert(out_f, assert);

	fido_dev_close(dev);
	fido_dev_free(&dev);
	fido_assert_free(&assert);

	exit(0);
}
