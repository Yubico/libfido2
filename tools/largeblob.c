/*
 * Copyright (c) 2020 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <fido.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "../openbsd-compat/openbsd-compat.h"
#include "extern.h"

static void
read_key(const char *path, struct blob *key)
{
	FILE	*f = NULL;

	f = open_read(path);
	if (base64_read(f, key) < 0)
		errx(1, "key input error");

	fclose(f);
	f = NULL;
}

static void
print_blob(const struct blob *blob)
{
	FILE  *f = NULL;

	f = open_write(NULL);

	if (fwrite(blob->ptr, blob->len, 1, f) != 1)
		errx(1, "fwrite");

	fclose(f);
	f = NULL;
}

static void
clear_key(struct blob *key)
{
	if (key->ptr != NULL)
		explicit_bzero(key->ptr, key->len);
	free(key->ptr);
	key->ptr = NULL;
	key->len = 0;
}

int
blob_get(const char *device_path, const char *key_path)
{
	fido_dev_t	*dev = NULL;
	struct blob	 blob;
	struct blob	 key;
	int		 r;

	memset(&blob, 0, sizeof(blob));
	memset(&key, 0, sizeof(key));

	read_key(key_path, &key);

	dev = open_dev(device_path);

	r = fido_dev_largeblob_get(dev, key.ptr, key.len, &blob.ptr, &blob.len);

	clear_key(&key);

	if (r != FIDO_OK)
		errx(1, "fido_dev_largeblob_get: %s", fido_strerr(r));

	print_blob(&blob);

	freezero(blob.ptr, blob.len);
	fido_dev_close(dev);
	fido_dev_free(&dev);

	exit(0);
}

static void
read_blob(struct blob *blob)
{
	FILE *f = NULL;

	f = open_read(NULL);
	if (base64_read(f, blob) < 0)
		errx(1, "blob input error");
	fclose(f);
	f = NULL;
}

int
blob_set(const char *device_path, const char *key_path)
{
	fido_dev_t	*dev = NULL;
	struct blob	 blob;
	struct blob	 key;
	char		 pin[1024];
	char		 prompt[1024];
	int		 r;

	memset(&blob, 0, sizeof(blob));
	memset(&key, 0, sizeof(key));

	read_key(key_path, &key);
	read_blob(&blob);

	dev = open_dev(device_path);

	r = fido_dev_largeblob_set(dev, key.ptr, key.len, blob.ptr, blob.len,
	    NULL);
	if (r == FIDO_ERR_PIN_REQUIRED) {
		r = snprintf(prompt, sizeof(prompt), "Enter PIN for %s: ", device_path);
		if (r < 0 || (size_t)r >= sizeof(prompt))
			errx(1, "snprintf");
		if (!readpassphrase(prompt, pin, sizeof(pin), RPP_ECHO_OFF))
			errx(1, "readpassphrase");
		r = fido_dev_largeblob_set(dev, key.ptr, key.len, blob.ptr,
		    blob.len, pin);
	}

	explicit_bzero(pin, sizeof(pin));
	clear_key(&key);
	freezero(blob.ptr, blob.len);

	if (r != FIDO_OK)
		errx(1, "fido_dev_largeblob_set: %s", fido_strerr(r));

	fido_dev_close(dev);
	fido_dev_free(&dev);

	exit(0);
}

int
blob_delete(const char* device_path, const char* key_path)
{
	fido_dev_t	*dev = NULL;
	struct blob	 key;
	char		 pin[1024];
	char		 prompt[1024];
	int		 r;

	read_key(key_path, &key);

	dev = open_dev(device_path);

	r = fido_dev_largeblob_remove(dev, key.ptr, key.len, NULL);
	if (r == FIDO_ERR_PIN_REQUIRED) {
		r = snprintf(prompt, sizeof(prompt), "Enter PIN for %s: ", device_path);
		if (r < 0 || (size_t)r >= sizeof(prompt))
			errx(1, "snprintf");
		if (!readpassphrase(prompt, pin, sizeof(pin), RPP_ECHO_OFF))
			errx(1, "readpassphrase");
		r = fido_dev_largeblob_remove(dev, key.ptr, key.len, pin);
	}

	explicit_bzero(pin, sizeof(pin));

	if (r != FIDO_OK)
		errx(1, "fido_dev_largeblob_remove: %s", fido_strerr(r));

	fido_dev_close(dev);
	fido_dev_free(&dev);

	exit(0);
}

int
blob_clean(const char *device_path)
{
	(void)device_path;
	errx(1, "unimplemented, sorry"); /* XXX fix me */
}
