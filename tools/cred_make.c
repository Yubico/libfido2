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

static fido_cred_t *
prepare_cred(FILE *in_f, int type, bool rk, bool uv, bool debug)
{
	fido_cred_t *cred = NULL;
	struct blob cdh;
	struct blob uid;
	char *rpid = NULL;
	char *uname = NULL;
	int r;

	memset(&cdh, 0, sizeof(cdh));
	memset(&uid, 0, sizeof(uid));

	r = base64_read(in_f, &cdh);
	r |= string_read(in_f, &rpid);
	r |= string_read(in_f, &uname);
	r |= base64_read(in_f, &uid);
	if (r < 0)
		errx(1, "input error");

	if (debug) {
		fprintf(stderr, "client data hash:\n");
		xxd(cdh.ptr, cdh.len);
		fprintf(stderr, "relying party id: %s\n", rpid);
		fprintf(stderr, "user name: %s\n", uname);
		fprintf(stderr, "user id:\n");
		xxd(uid.ptr, uid.len);
	}

	if ((cred = fido_cred_new()) == NULL)
		errx(1, "fido_cred_new");

	if ((r = fido_cred_set_type(cred, type)) != FIDO_OK ||
	    (r = fido_cred_set_clientdata_hash(cred, cdh.ptr,
	    cdh.len)) != FIDO_OK ||
	    (r = fido_cred_set_rp(cred, rpid, NULL)) != FIDO_OK ||
	    (r = fido_cred_set_user(cred, uid.ptr, uid.len, uname, NULL,
	    NULL)) != FIDO_OK ||
	    (r = fido_cred_set_options(cred, rk, uv)) != FIDO_OK)
		errx(1, "fido_cred_set: %s", fido_strerr(r));

	free(cdh.ptr);
	free(uid.ptr);
	free(rpid);
	free(uname);

	return (cred);
}

static void
print_cred(FILE *out_f, const fido_cred_t *cred)
{
	char *cdh = NULL;
	char *authdata = NULL;
	char *id = NULL;
	char *sig = NULL;
	char *x5c = NULL;
	int r;

	r = base64_encode(fido_cred_clientdata_hash_ptr(cred),
	    fido_cred_clientdata_hash_len(cred), &cdh);
	r |= base64_encode(fido_cred_authdata_ptr(cred),
	    fido_cred_authdata_len(cred), &authdata);
	r |= base64_encode(fido_cred_id_ptr(cred), fido_cred_id_len(cred),
	    &id);
	r |= base64_encode(fido_cred_sig_ptr(cred), fido_cred_sig_len(cred),
	    &sig);
	r |= base64_encode(fido_cred_x5c_ptr(cred), fido_cred_x5c_len(cred),
	    &x5c);
	if (r < 0)
		errx(1, "output error");

	fprintf(out_f, "%s\n", cdh);
	fprintf(out_f, "%s\n", fido_cred_rp_id(cred));
	fprintf(out_f, "%s\n", fido_cred_fmt(cred));
	fprintf(out_f, "%s\n", authdata);
	fprintf(out_f, "%s\n", id);
	fprintf(out_f, "%s\n", sig);
	fprintf(out_f, "%s\n", x5c);

	free(cdh);
	free(authdata);
	free(id);
	free(sig);
	free(x5c);
}

int
cred_make(int argc, char **argv)
{
	fido_dev_t *dev = NULL;
	fido_cred_t *cred = NULL;
	char prompt[1024];
	char pin[1024];
	char *in_path = NULL;
	char *out_path = NULL;
	FILE *in_f = NULL;
	FILE *out_f = NULL;
	bool rk = false;
	bool u2f = false;
	bool uv = false;
	bool debug = false;
	bool quiet = false;
	int type = COSE_ES256;
	int ch;
	int r;

	while ((ch = getopt(argc, argv, "di:o:qruv")) != -1) {
		switch (ch) {
		case 'd':
			debug = true;
			break;
		case 'i':
			in_path = optarg;
			break;
		case 'o':
			out_path = optarg;
			break;
		case 'q':
			quiet = true;
			break;
		case 'r':
			rk = true;
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

	if (argc < 1 || argc > 2)
		usage();

	in_f = open_read(in_path);
	out_f = open_write(out_path);

	if (argc > 1) {
		if (strcmp(argv[1], "es256") == 0)
			type = COSE_ES256;
		else if (strcmp(argv[1], "rs256") == 0)
			type = COSE_RS256;
		else
			errx(1, "unknown type %s", argv[1]);
	}

	fido_init(debug ? FIDO_DEBUG : 0);

	dev = open_dev(argv[0]);
	if (u2f)
		fido_dev_force_u2f(dev);

	cred = prepare_cred(in_f, type, rk, uv, debug);

	r = fido_dev_make_cred(dev, cred, NULL);
	if (r == FIDO_ERR_PIN_REQUIRED && !quiet) {
		r = snprintf(prompt, sizeof(prompt), "Enter PIN for %s: ",
		    argv[0]);
		if (r < 0 || (size_t)r >= sizeof(prompt))
			errx(1, "snprintf");
		if (!readpassphrase(prompt, pin, sizeof(pin), RPP_ECHO_OFF))
			errx(1, "readpassphrase");
		r = fido_dev_make_cred(dev, cred, pin);
	}

	explicit_bzero(pin, sizeof(pin));
	if (r != FIDO_OK)
		errx(1, "fido_dev_make_cred: %s", fido_strerr(r));
	print_cred(out_f, cred);

	fido_dev_close(dev);
	fido_dev_free(&dev);
	fido_cred_free(&cred);

	fclose(in_f);
	fclose(out_f);
	in_f = NULL;
	out_f = NULL;

	exit(0);
}
