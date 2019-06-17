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
mgmt_meta(int argc, char **argv)
{
	fido_dev_t *dev = NULL;
	fido_cred_mgmt_meta_t *meta = NULL;
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

	if ((meta = fido_cred_mgmt_meta_new()) == NULL)
		errx(1, "fido_cred_mgmt_meta_new");

	fido_init(debug ? FIDO_DEBUG : 0);

	dev = open_dev(argc, argv);
	read_pin(argv[0], pin, sizeof(pin));

	if ((r = fido_dev_cred_mgmt_get_meta(dev, meta, pin)) != FIDO_OK) {
		warnx("fido_dev_cred_mgmt_get_meta: %s", fido_strerr(r));
		status = 1;
	} else {
		printf("%u\n%u\n",
		    (unsigned)fido_cred_mgmt_meta_rk_existing(meta),
		    (unsigned)fido_cred_mgmt_meta_rk_remaining(meta));
	}

	fido_cred_mgmt_meta_free(&meta);
	fido_dev_close(dev);
	fido_dev_free(&dev);

	explicit_bzero(pin, sizeof(pin));

	exit(status);
}
