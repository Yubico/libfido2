/*
 * Copyright (c) 2019 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "extern.h"

void
usage(void)
{
	fprintf(stderr,
"usage: fido2-cred-mgmt [-MR] [-d] device\n"
"       fido2-cred-mgmt -D [-d] cred_id device\n" 
"       fido2-cred-mgmt -K [-d] rp_id device\n" 
"       fido2-cred-mgmt -V\n" 
	);

	exit(1);
}

int
main(int argc, char **argv)
{
	if (argc < 2 || strlen(argv[1]) != 2 || argv[1][0] != '-')
		usage();

	switch (argv[1][1]) {
	case 'D':
		return (mgmt_del_rk(--argc, ++argv));
	case 'K':
		return (mgmt_rk(--argc, ++argv));
	case 'M':
		return (mgmt_metadata(--argc, ++argv));
	case 'R':
		return (mgmt_rp(--argc, ++argv));
	case 'V':
		fprintf(stderr, "%d.%d.%d\n", _FIDO_MAJOR, _FIDO_MINOR,
		    _FIDO_PATCH);
		exit(0);
	}

	usage();

	/* NOTREACHED */
}
