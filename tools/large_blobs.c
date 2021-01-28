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
print_blob(const fido_blob_t *blob)
{
	FILE  *f = NULL;

	f = open_write(NULL);

	if (fwrite(fido_blob_ptr(blob), fido_blob_len(blob), 1, f) != 1)
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
	fido_blob_t	*blob = NULL;
	struct blob	 key;
	int		 r;

	memset(&key, 0, sizeof(key));

	if ((blob = fido_blob_new()) == NULL)
		errx(1, "fido_blob_new");

	read_key(key_path, &key);

	dev = open_dev(device_path);

	r = fido_dev_large_blob_get(dev, key.ptr, key.len, blob);

	clear_key(&key);

	if (r != FIDO_OK)
		errx(1, "fido_dev_large_blob_get: %s", fido_strerr(r));

	print_blob(blob);

	fido_blob_free(&blob);
	fido_dev_close(dev);
	fido_dev_free(&dev);

	exit(0);
}

static void
read_blob(fido_blob_t *blob)
{
	unsigned char buffer[1024];
	FILE	*f;
	size_t	 n;

	f = open_read(NULL);

	while ((n = fread(buffer, sizeof(unsigned char), sizeof(buffer), f)) > 0)
		if (fido_blob_append(blob, buffer, n) != FIDO_OK)
			errx(1,"fido_blob_append");

	if (ferror(f))
		errx(1, "fread");

	fclose(f);
	f = NULL;
}

int
blob_set(const char *device_path, const char *key_path)
{
	fido_dev_t	*dev = NULL;
	fido_blob_t	*blob = NULL;
	struct blob	 key;
	char		 pin[1024];
	char		 prompt[1024];
	int		 r;

	memset(&key, 0, sizeof(key));

	if ((blob = fido_blob_new()) == NULL)
		errx(1, "fido_blob_new");

	read_key(key_path, &key);
	read_blob(blob);

	dev = open_dev(device_path);

	r = fido_dev_large_blob_put(dev, key.ptr, key.len, blob, NULL);
	if (r == FIDO_ERR_PIN_REQUIRED) {
		r = snprintf(prompt, sizeof(prompt), "Enter PIN for %s: ", device_path);
		if (r < 0 || (size_t)r >= sizeof(prompt))
			errx(1, "snprintf");
		if (!readpassphrase(prompt, pin, sizeof(pin), RPP_ECHO_OFF))
			errx(1, "readpassphrase");
		r = fido_dev_large_blob_put(dev, key.ptr, key.len, blob, pin);
	}

	explicit_bzero(pin, sizeof(pin));
	clear_key(&key);

	if (r != FIDO_OK)
		errx(1, "fido_dev_large_blob_set: %s", fido_strerr(r));

	fido_blob_free(&blob);
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

	r = fido_dev_large_blob_remove(dev, key.ptr, key.len, NULL);
	if (r == FIDO_ERR_PIN_REQUIRED) {
		r = snprintf(prompt, sizeof(prompt), "Enter PIN for %s: ", device_path);
		if (r < 0 || (size_t)r >= sizeof(prompt))
			errx(1, "snprintf");
		if (!readpassphrase(prompt, pin, sizeof(pin), RPP_ECHO_OFF))
			errx(1, "readpassphrase");
		r = fido_dev_large_blob_remove(dev, key.ptr, key.len, pin);
	}

	explicit_bzero(pin, sizeof(pin));

	if (r != FIDO_OK)
		errx(1, "fido_dev_large_blob_remove: %s", fido_strerr(r));

	fido_dev_close(dev);
	fido_dev_free(&dev);

	exit(0);
}

int
blob_clean(const char *device_path)
{
	fido_dev_t	*dev = NULL;
	char		 pin[1024];
	char		 prompt[1024];
	int		 r;

	dev = open_dev(device_path);

	r = fido_dev_large_blob_trim(dev, NULL);
	if (r == FIDO_ERR_PIN_REQUIRED || r == FIDO_ERR_INVALID_ARGUMENT) {
		r = snprintf(prompt, sizeof(prompt), "Enter PIN for %s: ", device_path);
		if (r < 0 || (size_t)r >= sizeof(prompt))
			errx(1, "snprintf");
		if (!readpassphrase(prompt, pin, sizeof(pin), RPP_ECHO_OFF))
			errx(1, "readpassphrase");
		r = fido_dev_large_blob_trim(dev, pin);
	}

	explicit_bzero(pin, sizeof(pin));

	if (r != FIDO_OK)
		errx(1, "fido_dev_large_blob_trim: %s", fido_strerr(r));

	fido_dev_close(dev);
	fido_dev_free(&dev);

	exit(0);
}
