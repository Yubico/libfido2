/*
 * Copyright (c) 2019 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "extern.h"

static int action;

void
usage(void)
{
	fprintf(stderr,
"usage: fido2-credman [-d] [-MR] device\n"
"       fido2-credman [-d] -D cred_id device\n" 
"       fido2-credman [-d] -K rp_id device\n" 
	);

	exit(1);
}

static void
setaction(int ch)
{
	if (action)
		usage();
	action = ch;
}

int
main(int argc, char **argv)
{
	int ch;
	int flags = 0;

	while ((ch = getopt(argc, argv, "DKMRd")) != -1) {
		switch (ch) {
		case 'd':
			flags = FIDO_DEBUG;
			break;
		default:
			setaction(ch);
			break;
		}
	}

	argc -= optind;
	argv += optind;

	fido_init(flags);

	if (argc < 1)
		usage();

	switch (action) {
	case 'D':
		return (credman_del_rk(argc, argv));
	case 'K':
		return (credman_rk(argc, argv));
	case 'M':
		return (credman_metadata(argc, argv));
	case 'R':
		return (credman_rp(argc, argv));
	}

	usage();

	/* NOTREACHED */
}
