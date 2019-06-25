/*
 * Copyright (c) 2019 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <fido.h>
#include <fido/credman.h>

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "../openbsd-compat/openbsd-compat.h"
#include "extern.h"

int
credman_metadata(int argc, char **argv)
{
	fido_dev_t *dev = NULL;
	fido_credman_metadata_t *metadata = NULL;
	char pin[1024];
	int r;

	if (argc < 1)
		usage();
	if ((metadata = fido_credman_metadata_new()) == NULL)
		errx(1, "fido_credman_metadata_new");

	dev = open_dev(argv[0]);
	read_pin(argv[0], pin, sizeof(pin));
	r = fido_credman_get_dev_metadata(dev, metadata, pin);
	explicit_bzero(pin, sizeof(pin));

	if (r != FIDO_OK)
		errx(1, "fido_credman_get_dev_metadata: %s", fido_strerr(r));

	printf("%u\n%u\n", (unsigned)fido_credman_rk_existing(metadata),
	    (unsigned)fido_credman_rk_remaining(metadata));

	fido_credman_metadata_free(&metadata);
	fido_dev_close(dev);
	fido_dev_free(&dev);

	exit(0);
}

static void
print_rp(fido_credman_rp_t *rp)
{
	const unsigned char *p;
	size_t n;

	for (size_t i = 0; i < fido_credman_rp_count(rp); i++) {
		p = fido_credman_rp_id_hash_ptr(rp, i);
		n = fido_credman_rp_id_hash_len(rp, i);

		if (n == 0)
			printf("<rp id hash omitted>");
		else {
			while (n--)
				printf("%02x", *p++);
		}

		if (fido_credman_rp_id(rp, i) == NULL)
			printf(" <rp id omitted>\n");
		else
			printf(" %s\n", fido_credman_rp_id(rp, i));
	}
}

int
credman_rp(int argc, char **argv)
{
	fido_dev_t *dev = NULL;
	fido_credman_rp_t *rp = NULL;
	char pin[1024];
	int r;

	if (argc < 1)
		usage();
	if ((rp = fido_credman_rp_new()) == NULL)
		errx(1, "fido_credman_rp_new");

	dev = open_dev(argv[0]);
	read_pin(argv[0], pin, sizeof(pin));
	r = fido_credman_get_dev_rp(dev, rp, pin);
	explicit_bzero(pin, sizeof(pin));

	if (r != FIDO_OK)
		errx(1, "fido_credman_get_dev_rp: %s", fido_strerr(r));

	print_rp(rp);

	fido_credman_rp_free(&rp);
	fido_dev_close(dev);
	fido_dev_free(&dev);

	exit(0);
}

static void
print_rk(const fido_cred_t *cred)
{
	char *user_id = NULL;

	if (base64_encode(fido_cred_user_id_ptr(cred),
	    fido_cred_user_id_len(cred), &user_id) < 0)
		errx(1, "output error");

	printf("%s\n", user_id);
	printf("%s\n", fido_cred_user_name(cred));
	printf("%s\n", fido_cred_display_name(cred));
	print_cred(stdout, fido_cred_type(cred), cred);

	free(user_id);
	user_id = NULL;
}

int
credman_rk(int argc, char **argv)
{
	fido_dev_t *dev = NULL;
	fido_credman_rk_t *rk = NULL;
	char pin[1024];
	int r;

	if (argc < 2)
		usage();
	if ((rk = fido_credman_rk_new()) == NULL)
		errx(1, "fido_credman_rk_new");

	dev = open_dev(argv[1]);
	read_pin(argv[1], pin, sizeof(pin));
	r = fido_credman_get_dev_rk(dev, argv[0], rk, pin);
	explicit_bzero(pin, sizeof(pin));

	if (r != FIDO_OK)
		errx(1, "fido_credman_get_dev_rk: %s", fido_strerr(r));
	for (size_t i = 0; i < fido_credman_rk_count(rk); i++)
		print_rk(fido_credman_rk(rk, i));

	fido_credman_rk_free(&rk);
	fido_dev_close(dev);
	fido_dev_free(&dev);

	exit(0);
}

int
credman_del_rk(int argc, char **argv)
{
	fido_dev_t	*dev = NULL;
	char		 pin[1024];
	void		*cred_id = NULL;
	size_t		 cred_id_len = 0;
	int		 r;

	if (argc < 2)
		usage();
	if (base64_decode(argv[0], &cred_id, &cred_id_len) < 0)
		errx(1, "base64_decode");

	dev = open_dev(argv[1]);
	read_pin(argv[1], pin, sizeof(pin));
	r = fido_credman_del_dev_rk(dev, cred_id, cred_id_len, pin);
	explicit_bzero(pin, sizeof(pin));

	if (r != FIDO_OK)
		errx(1, "fido_credman_del_dev_rk: %s", fido_strerr(r));

	fido_dev_close(dev);
	fido_dev_free(&dev);
	free(cred_id);
	cred_id = NULL;

	exit(0);
}
