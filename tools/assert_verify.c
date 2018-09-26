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
#include <fido/es256.h>
#include <fido/rs256.h>

#include "../openbsd-compat/openbsd-compat.h"
#include "extern.h"

static fido_assert_t *
prepare_assert(FILE *in_f, bool up, bool uv, bool debug)
{
	fido_assert_t *assert = NULL;
	struct blob cdh;
	struct blob authdata;
	struct blob sig;
	char *rpid = NULL;
	int r;

	memset(&cdh, 0, sizeof(cdh));
	memset(&authdata, 0, sizeof(authdata));
	memset(&sig, 0, sizeof(sig));

	r = base64_read(in_f, &cdh);
	r |= string_read(in_f, &rpid);
	r |= base64_read(in_f, &authdata);
	r |= base64_read(in_f, &sig);
	if (r < 0)
		errx(1, "input error");

	if (debug) {
		fprintf(stderr, "client data hash:\n");
		xxd(cdh.ptr, cdh.len);
		fprintf(stderr, "relying party id: %s\n", rpid);
		fprintf(stderr, "authenticator data:\n");
		xxd(authdata.ptr, authdata.len);
		fprintf(stderr, "signature:\n");
		xxd(sig.ptr, sig.len);
	}

	if ((assert = fido_assert_new()) == NULL)
		errx(1, "fido_assert_new");
	if ((r = fido_assert_set_count(assert, 1)) != FIDO_OK)
		errx(1, "fido_assert_count: %s", fido_strerr(r));

	if ((r = fido_assert_set_clientdata_hash(assert, cdh.ptr,
	    cdh.len)) != FIDO_OK ||
	    (r = fido_assert_set_rp(assert, rpid)) != FIDO_OK ||
	    (r = fido_assert_set_authdata(assert, 0, authdata.ptr,
	    authdata.len)) != FIDO_OK ||
	    (r = fido_assert_set_options(assert, up, uv)) != FIDO_OK ||
	    (r = fido_assert_set_sig(assert, 0, sig.ptr, sig.len)) != FIDO_OK)
		errx(1, "fido_assert_set: %s", fido_strerr(r));

	free(cdh.ptr);
	free(authdata.ptr);
	free(sig.ptr);
	free(rpid);

	return (assert);
}

static void *
load_pubkey(int type, const char *file)
{
	EC_KEY *ec = NULL;
	RSA *rsa = NULL;
	es256_pk_t *es256_pk = NULL;
	rs256_pk_t *rs256_pk = NULL;
	void *pk = NULL;

	if (type == COSE_ES256) {
		if ((ec = read_ec_pubkey(file)) == NULL)
			errx(1, "read_ec_pubkey");
		if ((es256_pk = es256_pk_new()) == NULL)
			errx(1, "es256_pk_new");
		if (es256_pk_from_EC_KEY(es256_pk, ec) != FIDO_OK)
			errx(1, "es256_pk_from_EC_KEY");

		pk = es256_pk;
		EC_KEY_free(ec);
	} else {
		if ((rsa = read_rsa_pubkey(file)) == NULL)
			errx(1, "read_rsa_pubkey");
		if ((rs256_pk = rs256_pk_new()) == NULL)
			errx(1, "rs256_pk_new");
		if (rs256_pk_from_RSA(rs256_pk, rsa) != FIDO_OK)
			errx(1, "rs256_pk_from_RSA");

		pk = rs256_pk;
		RSA_free(rsa);
	}

	return (pk);
}

int
assert_verify(int argc, char **argv)
{
	fido_assert_t *assert = NULL;
	void *pk = NULL;
	char *in_path = NULL;
	FILE *in_f = NULL;
	bool up = false;
	bool uv = false;
	bool debug = false;
	int type = COSE_ES256;
	int ch;
	int r;

	while ((ch = getopt(argc, argv, "di:pv")) != -1) {
		switch (ch) {
		case 'd':
			debug = true;
			break;
		case 'i':
			in_path = optarg;
			break;
		case 'p':
			up = true;
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

	if (argc < 1 || argc > 2)
		usage();

	in_f = open_read(in_path);

	if (argc > 1) {
		if (strcmp(argv[1], "es256") == 0)
			type = COSE_ES256;
		else if (strcmp(argv[1], "rs256") == 0)
			type = COSE_RS256;
		else
			errx(1, "unknown type %s", argv[1]);
	}

	fido_init(debug ? FIDO_DEBUG : 0);
	pk = load_pubkey(type, argv[0]);
	assert = prepare_assert(in_f, up, uv, debug);
	if ((r = fido_assert_verify(assert, 0, type, pk)) != FIDO_OK)
		errx(1, "fido_assert_verify: %s", fido_strerr(r));
	fido_assert_free(&assert);

	fclose(in_f);
	in_f = NULL;

	exit(0);
}
