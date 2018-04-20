/*
 * Copyright (c) 2018 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <sys/types.h>

#ifdef __linux__
#include <sys/ioctl.h>
#include <linux/hidraw.h>
#endif

#include <fcntl.h>
#include <hidapi.h>
#include <string.h>
#include <unistd.h>

#include "fido.h"

#ifdef __linux__
static int
get_key_len(uint8_t tag, uint8_t *key, size_t *key_len)
{
	*key = tag & 0xfc;
	if ((*key & 0xf0) == 0xf0) {
		return (-1);
	}

	*key_len = tag & 0x3;
	if (*key_len == 3) {
		*key_len = 4;
	}

	return (0);
}

static int
get_key_val(const void *body, size_t key_len, uint32_t *val)
{
	const uint8_t *ptr = body;

	switch (key_len) {
	case 0:
		*val = 0;
		break;
	case 1:
		*val = ptr[0];
		break;
	case 2:
		*val = (uint32_t)((ptr[1] << 8) | ptr[0]);
		break;
	default:
		return (-1);
	}

	return (0);
}

static int
get_usage_info(const struct hidraw_report_descriptor *hrd, uint32_t *usage_page,
    uint32_t *usage)
{
	const uint8_t	*ptr;
	size_t		 len;

	ptr = hrd->value;
	len = hrd->size;

	while (len > 0) {
		const uint8_t tag = ptr[0];
		ptr++;
		len--;

		uint8_t  key;
		size_t   key_len;
		uint32_t key_val;

		if (get_key_len(tag, &key, &key_len) < 0 || key_len > len ||
		    get_key_val(ptr, key_len, &key_val) < 0) {
			return (-1);
		}

		if (key == 0x4) {
			*usage_page = key_val;
		} else if (key == 0x8) {
			*usage = key_val;
		}

		ptr += key_len;
		len -= key_len;
	}

	return (0);
}

static int
get_report_descriptor(const char *path, struct hidraw_report_descriptor *hrd)
{
	int	r;
	int	s = -1;
	int	fd;
	int	ok = -1;

	if ((fd = open(path, O_RDONLY)) < 0)
		return (-1);

	if ((r = ioctl(fd, HIDIOCGRDESCSIZE, &s)) < 0 || s < 0 ||
	    (unsigned)s > HID_MAX_DESCRIPTOR_SIZE)
		goto fail;

	hrd->size = s;

	if ((r = ioctl(fd, HIDIOCGRDESC, hrd)) < 0)
		goto fail;

	ok = 0;
fail:
	if (fd != -1)
		close(fd);

	return (ok);
}
#endif /* __linux__ */

static bool
is_fido(const struct hid_device_info *d)
{
	uint32_t usage = 0;
	uint32_t usage_page = 0;
#ifdef __linux__
	struct hidraw_report_descriptor hrd;

	memset(&hrd, 0, sizeof(hrd));
	if (get_report_descriptor(d->path, &hrd) < 0 ||
	    get_usage_info(&hrd, &usage_page, &usage) < 0) {
		return (false);
	}
#else
	(void)usage;
	usage_page = d->usage_page;
#endif

	return (usage_page == 0xf1d0);
}

static int
copy_info(fido_dev_info_t *di, const struct hid_device_info *d)
{
	memset(di, 0, sizeof(*di));

	if (is_fido(d) == false)
		goto fail;

	di->path = strdup(d->path);
	di->manufacturer = wcsdup(d->manufacturer_string);
	di->product = wcsdup(d->product_string);
	di->vendor_id = d->vendor_id;
	di->product_id = d->product_id;

	if (di->path == NULL ||
	    di->manufacturer == NULL ||
	    di->product == NULL)
		goto fail;

	return (0);
fail:
	free(di->path);
	free(di->manufacturer);
	free(di->product);

	explicit_bzero(di, sizeof(*di));

	return (-1);
}

int
fido_dev_info_manifest(fido_dev_info_t *devlist, size_t ilen, size_t *olen)
{
	struct hid_device_info *hdi;

	*olen = 0;

	if (ilen == 0)
		return (FIDO_OK); /* nothing to do */

	if (devlist == NULL)
		return (FIDO_ERR_INVALID_ARGUMENT);

	if ((hdi = hid_enumerate(0, 0)) == NULL)
		return (FIDO_OK); /* nothing to do */

	for (struct hid_device_info *d = hdi; d != NULL; d = d->next) {
		if (copy_info(&devlist[*olen], d) == 0) {
			if (++(*olen) == ilen)
				break;
		}
	}

	hid_free_enumeration(hdi);

	return (FIDO_OK);
}

/*
 * get/set functions for fido_dev_info_t; always at the end of the file
 */

fido_dev_info_t *
fido_dev_info_new(size_t n)
{
	return (recallocarray(NULL, 0, n, sizeof(fido_dev_info_t)));
}

void
fido_dev_info_free(fido_dev_info_t **devlist_p, size_t n)
{
	fido_dev_info_t *devlist;

	if (devlist_p == NULL || (devlist = *devlist_p) == NULL)
		return;

	for (size_t i = 0; i < n; i++) {
		const fido_dev_info_t *di = &devlist[i];
		free(di->path);
		free(di->manufacturer);
		free(di->product);
	}

	free(devlist);

	*devlist_p = NULL;
}

const fido_dev_info_t *
fido_dev_info_ptr(const fido_dev_info_t *devlist, size_t i)
{
	return (&devlist[i]);
}

const char *
fido_dev_info_path(const fido_dev_info_t *di)
{
	return (di->path);
}

int16_t
fido_dev_info_vendor(const fido_dev_info_t *di)
{
	return (di->vendor_id);
}

int16_t
fido_dev_info_product(const fido_dev_info_t *di)
{
	return (di->product_id);
}

const wchar_t *
fido_dev_info_manufacturer_string(const fido_dev_info_t *di)
{
	return (di->manufacturer);
}

const wchar_t *
fido_dev_info_product_string(const fido_dev_info_t *di)
{
	return (di->product);
}
