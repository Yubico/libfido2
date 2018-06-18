/*
 * Copyright (c) 2018 Yubico AB. All rights reserved.
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
"usage: fido2-token [-CIRS] [-d] device\n"
"       fido2-token -L [-d]\n" 
"       fido2-token -V\n" 
	);

	exit(1);
}

int
main(int argc, char **argv)
{
	if (argc < 2 || strlen(argv[1]) != 2 || argv[1][0] != '-')
		usage();

	switch (argv[1][1]) {
	case 'C':
		return (pin_change(--argc, ++argv));
	case 'I':
		return (token_info(--argc, ++argv));
	case 'L':
		return (token_list(--argc, ++argv));
	case 'R':
		return (token_reset(--argc, ++argv));
	case 'S':
		return (pin_set(--argc, ++argv));
	case 'V':
		fprintf(stderr, "%d.%d.%d\n", _FIDO_MAJOR, _FIDO_MINOR,
		    _FIDO_PATCH);
		exit(0);
	}

	usage();

	/* NOTREACHED */
}
