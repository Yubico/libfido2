/*
 * Copyright (c) 2018 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <sys/types.h>
#include <sys/stat.h>

#include <fcntl.h>
#include <hidapi.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fido.h"

#if defined(_WIN32)
#include <windows.h>

#include <winternl.h>
#include <ntstatus.h>
#include <winerror.h>
#include <stdio.h>
#include <bcrypt.h>
#include <sal.h>

static int
obtain_nonce(uint64_t *nonce)
{
	NTSTATUS status;

	status = BCryptGenRandom(NULL, (unsigned char *)nonce, sizeof(*nonce),
	    BCRYPT_USE_SYSTEM_PREFERRED_RNG);

	if (!NT_SUCCESS(status))
		return (-1);

	return (0);
}
#elif defined(HAS_DEV_URANDOM)
static int
obtain_nonce(uint64_t *nonce)
{
	int	fd = -1;
	int	ok = -1;
	ssize_t	r;

	if ((fd = open(FIDO_RANDOM_DEV, O_RDONLY)) < 0)
		goto fail;
	if ((r = read(fd, nonce, sizeof(*nonce))) < 0 ||
	    (size_t)r != sizeof(*nonce))
		goto fail;

	ok = 0;
fail:
	if (fd != -1)
		close(fd);

	return (ok);
}
#else
#error "please provide an implementation of obtain_nonce() for your platform"
#endif /* _WIN32 */

static int
fido_dev_open_tx(fido_dev_t *dev, const char *path)
{
	const uint8_t cmd = CTAP_FRAME_INIT | CTAP_CMD_INIT;

	if (dev->hid != NULL)
		return (FIDO_ERR_INVALID_ARGUMENT);

	if (obtain_nonce(&dev->nonce) < 0 ||
	    (dev->hid = hid_open_path(path)) == NULL)
		return (FIDO_ERR_INTERNAL);

	if (tx(dev, cmd, &dev->nonce, sizeof(dev->nonce)) < 0) {
		hid_close(dev->hid);
		dev->hid = NULL;
		return (FIDO_ERR_TX);
	}

	return (FIDO_OK);
}

static int
fido_dev_open_rx(fido_dev_t *dev, int ms)
{
	const uint8_t	cmd = CTAP_FRAME_INIT | CTAP_CMD_INIT;
	int		r;

	if ((r = rx(dev, cmd, &dev->attr, sizeof(dev->attr), ms)) < 0 ||
	    (size_t)r != sizeof(dev->attr) || dev->attr.nonce != dev->nonce)
		return (FIDO_ERR_RX);

	dev->cid = dev->attr.cid;

	return (FIDO_OK);
}

static int
fido_dev_open_wait(fido_dev_t *dev, const char *path, int ms)
{
	int r;

	if ((r = fido_dev_open_tx(dev, path)) != FIDO_OK ||
	    (r = fido_dev_open_rx(dev, ms)) != FIDO_OK)
		return (r);

	return (FIDO_OK);
}

int
fido_dev_open(fido_dev_t *dev, const char *path)
{
	return (fido_dev_open_wait(dev, path, -1));
}

int
fido_dev_close(fido_dev_t *dev)
{
	if (dev->hid == NULL)
		return (FIDO_ERR_INVALID_ARGUMENT);

	hid_close(dev->hid);
	dev->hid = NULL;

	return (FIDO_OK);
}

void
fido_init(void)
{
	if (getenv("FIDO_DEBUG") != NULL)
		debug = 1;
}

/*
 * get/set functions for fido_dev_t; always at the end of the file
 */

fido_dev_t *
fido_dev_new(void)
{
	fido_dev_t *dev;

	if ((dev = calloc(1, sizeof(*dev))) == NULL)
		return (NULL);

	dev->cid = CTAP_CID_BROADCAST;

	return (dev);
}

void
fido_dev_free(fido_dev_t **dev_p)
{
	fido_dev_t *dev;

	if (dev_p == NULL || (dev = *dev_p) == NULL)
		return;

	free(dev);

	*dev_p = NULL;
}

void *
fido_dev_hid(const fido_dev_t *dev)
{
	return (dev->hid);
}

uint32_t
fido_dev_cid(const fido_dev_t *dev)
{
	return (dev->cid);
}

uint8_t
fido_dev_protocol(const fido_dev_t *dev)
{
	return (dev->attr.protocol);
}

uint8_t
fido_dev_major(const fido_dev_t *dev)
{
	return (dev->attr.major);
}

uint8_t
fido_dev_minor(const fido_dev_t *dev)
{
	return (dev->attr.minor);
}

uint8_t
fido_dev_build(const fido_dev_t *dev)
{
	return (dev->attr.build);
}

uint8_t
fido_dev_flags(const fido_dev_t *dev)
{
	return (dev->attr.flags);
}

bool
fido_dev_is_fido2(const fido_dev_t *dev)
{
	return (dev->attr.flags & FIDO_CAP_CBOR);
}

void
fido_dev_force_u2f(fido_dev_t *dev)
{
	dev->attr.flags &= ~FIDO_CAP_CBOR;
}
