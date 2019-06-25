/*
 * Copyright (c) 2018 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <fido.h>
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
pin_set(int argc, char **argv)
{
	fido_dev_t *dev = NULL;
	char prompt[1024];
	char pin1[1024];
	char pin2[1024];
	bool debug = false;
	int ch;
	int r;
	int status = 1;

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
	dev = open_dev(argv[0]);

	r = snprintf(prompt, sizeof(prompt), "Enter new PIN for %s: ", argv[0]);
	if (r < 0 || (size_t)r >= sizeof(prompt)) {
		warnx("snprintf");
		goto out;
	}

	if (!readpassphrase(prompt, pin1, sizeof(pin1), RPP_ECHO_OFF)) {
		warnx("readpassphrase");
		goto out;
	}

	r = snprintf(prompt, sizeof(prompt), "Enter the same PIN again: ");
	if (r < 0 || (size_t)r >= sizeof(prompt)) {
		warnx("snprintf");
		goto out;
	}

	if (!readpassphrase(prompt, pin2, sizeof(pin2), RPP_ECHO_OFF)) {
		warnx("readpassphrase");
		goto out;
	}

	if (strcmp(pin1, pin2) != 0) {
		fprintf(stderr, "PINs do not match. Try again.\n");
		goto out;
	}

	if ((r = fido_dev_set_pin(dev, pin1, NULL)) != FIDO_OK) {
		warnx("fido_dev_set_pin: %s", fido_strerr(r));
		goto out;
	}

	fido_dev_close(dev);
	fido_dev_free(&dev);

	status = 0;
out:
	explicit_bzero(pin1, sizeof(pin1));
	explicit_bzero(pin2, sizeof(pin2));

	exit(status);
}

int
pin_change(int argc, char **argv)
{
	fido_dev_t *dev = NULL;
	char prompt[1024];
	char pin0[1024];
	char pin1[1024];
	char pin2[1024];
	bool debug = false;
	int ch;
	int r;
	int status = 1;

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
	dev = open_dev(argv[0]);

	r = snprintf(prompt, sizeof(prompt), "Enter current PIN for %s: ",
	    argv[0]);
	if (r < 0 || (size_t)r >= sizeof(prompt)) {
		warnx("snprintf");
		goto out;
	}

	if (!readpassphrase(prompt, pin0, sizeof(pin0), RPP_ECHO_OFF)) {
		warnx("readpassphrase");
		goto out;
	}

	r = snprintf(prompt, sizeof(prompt), "Enter new PIN for %s: ", argv[0]);
	if (r < 0 || (size_t)r >= sizeof(prompt)) {
		warnx("snprintf");
		goto out;
	}

	if (!readpassphrase(prompt, pin1, sizeof(pin1), RPP_ECHO_OFF)) {
		warnx("readpassphrase");
		goto out;
	}

	r = snprintf(prompt, sizeof(prompt), "Enter the same PIN again: ");
	if (r < 0 || (size_t)r >= sizeof(prompt)) {
		warnx("snprintf");
		goto out;
	}

	if (!readpassphrase(prompt, pin2, sizeof(pin2), RPP_ECHO_OFF)) {
		warnx("readpassphrase");
		goto out;
	}

	if (strcmp(pin1, pin2) != 0) {
		fprintf(stderr, "PINs do not match. Try again.\n");
		goto out;
	}

	if ((r = fido_dev_set_pin(dev, pin1, pin0)) != FIDO_OK) {
		warnx("fido_dev_set_pin: %s", fido_strerr(r));
		goto out;
	}

	fido_dev_close(dev);
	fido_dev_free(&dev);

	status = 0;
out:
	explicit_bzero(pin0, sizeof(pin0));
	explicit_bzero(pin1, sizeof(pin1));
	explicit_bzero(pin2, sizeof(pin2));

	exit(status);
}
