/*
 * Copyright (c) 2018 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

/*
 * cc -fPIC -D_GNU_SOURCE -shared -o preload.so preload-fuzz.c
 * export LD_PRELOAD=$(realpath preload.so)
 */

#include <hidapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

hid_device *
hid_open_path(const char *path)
{
	/* return non-NULL handle */
	return ((void *)0xdeadbeef);
}

void
hid_close(hid_device *dev)
{
	/* nothing to do */
	return;
}

int
hid_write(hid_device *dev, const unsigned char *data, size_t len)
{
	/* fake write */
	return (len);
}

int
hid_read_timeout(hid_device *dev, unsigned char *data, size_t len, int ms)
{
	ssize_t r;

	if ((r = read(STDIN_FILENO, data, len)) < 0)
		return (0);

	return ((int)r);
}
