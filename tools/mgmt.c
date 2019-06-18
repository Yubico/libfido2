/*
 * Copyright (c) 2019 Yubico AB. All rights reserved.
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

int
mgmt_metadata(int argc, char **argv)
{
	fido_dev_t *dev = NULL;
	fido_cred_mgmt_metadata_t *metadata = NULL;
	char pin[1024];
	bool debug = false;
	int ch;
	int r;
	int status = 0;

	while ((ch = getopt(argc, argv, "d")) != -1) {
		switch (ch) {
		case 'd':
			debug = true;
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (argc < 1)
		usage();

	fido_init(debug ? FIDO_DEBUG : 0);

	if ((metadata = fido_cred_mgmt_metadata_new()) == NULL)
		errx(1, "fido_cred_mgmt_metadata_new");

	dev = open_dev(argv[0]);
	read_pin(argv[0], pin, sizeof(pin));

	if ((r = fido_dev_get_cred_mgmt_metadata(dev, metadata,
	    pin)) != FIDO_OK) {
		warnx("fido_dev_get_cred_mgmt_metadata: %s", fido_strerr(r));
		status = 1;
	} else {
		printf("%u\n%u\n",
		    (unsigned)fido_cred_mgmt_rk_existing(metadata),
		    (unsigned)fido_cred_mgmt_rk_remaining(metadata));
	}

	fido_cred_mgmt_metadata_free(&metadata);
	fido_dev_close(dev);
	fido_dev_free(&dev);

	explicit_bzero(pin, sizeof(pin));

	exit(status);
}

static void
print_rp(fido_cred_mgmt_rp_t *rp)
{
	const unsigned char *p;
	size_t n;

	for (size_t i = 0; i < fido_cred_mgmt_rp_count(rp); i++) {
		p = fido_cred_mgmt_rp_id_hash_ptr(rp, i);
		n = fido_cred_mgmt_rp_id_hash_len(rp, i);

		if (n == 0)
			printf("<rp id hash omitted>");
		else {
			while (n--)
				printf("%02x", *p++);
		}

		if (fido_cred_mgmt_rp_id(rp, i) == NULL)
			printf(" <rp id omitted>\n");
		else
			printf(" %s\n", fido_cred_mgmt_rp_id(rp, i));
	}
}

int
mgmt_rp(int argc, char **argv)
{
	fido_dev_t *dev = NULL;
	fido_cred_mgmt_rp_t *rp = NULL;
	char pin[1024];
	bool debug = false;
	int ch;
	int r;
	int status = 0;

	while ((ch = getopt(argc, argv, "d")) != -1) {
		switch (ch) {
		case 'd':
			debug = true;
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (argc < 1)
		usage();

	fido_init(debug ? FIDO_DEBUG : 0);

	if ((rp = fido_cred_mgmt_rp_new()) == NULL)
		errx(1, "fido_cred_mgmt_rp_new");

	dev = open_dev(argv[0]);
	read_pin(argv[0], pin, sizeof(pin));

	if ((r = fido_dev_get_cred_mgmt_rp(dev, rp, pin)) != FIDO_OK) {
		warnx("fido_dev_get_cred_mgmt_rp: %s", fido_strerr(r));
		status = 1;
	} else
		print_rp(rp);

	fido_cred_mgmt_rp_free(&rp);
	fido_dev_close(dev);
	fido_dev_free(&dev);

	explicit_bzero(pin, sizeof(pin));

	exit(status);
}

static void
print_rk(fido_cred_mgmt_rk_t *rk)
{
	const fido_cred_t *cred;
	char *id = NULL;

	for (size_t i = 0; i < fido_cred_mgmt_rk_count(rk); i++) {
		cred = fido_cred_mgmt_rk(rk, i);

		if (base64_encode(fido_cred_id_ptr(cred),
		    fido_cred_id_len(cred), &id) < 0)
			errx(1, "output error");

		printf("%s\n", id);
		free(id);
		id = NULL;

		printf("%s\n", fido_cred_user_name(cred));
		printf("%s\n", fido_cred_display_name(cred));
	}
}

int
mgmt_rk(int argc, char **argv)
{
	fido_dev_t *dev = NULL;
	fido_cred_mgmt_rk_t *rk = NULL;
	char pin[1024];
	bool debug = false;
	int ch;
	int r;
	int status = 0;

	while ((ch = getopt(argc, argv, "d")) != -1) {
		switch (ch) {
		case 'd':
			debug = true;
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (argc < 2)
		usage();

	fido_init(debug ? FIDO_DEBUG : 0);

	if ((rk = fido_cred_mgmt_rk_new()) == NULL)
		errx(1, "fido_cred_mgmt_rk_new");

	dev = open_dev(argv[1]);
	read_pin(argv[1], pin, sizeof(pin));

	if ((r = fido_dev_get_cred_mgmt_rk(dev, argv[0], rk, pin)) != FIDO_OK) {
		warnx("fido_dev_get_cred_mgmt_rk: %s", fido_strerr(r));
		status = 1;
	} else
		print_rk(rk);

	fido_cred_mgmt_rk_free(&rk);
	fido_dev_close(dev);
	fido_dev_free(&dev);

	explicit_bzero(pin, sizeof(pin));

	exit(status);
}
