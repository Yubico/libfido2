/*
 * Copyright (c) 2019 Google LLC. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <hidapi/hidapi.h>

#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#include "fido.h"

static size_t
fido_wcslen(const wchar_t *wcs)
{
	size_t l = 0;
	while (*wcs++ != L'\0')
		l++;
	return l;
}

static char *
wcs_to_cs(const wchar_t *wcs)
{
	char *cs;
	size_t i;

	if (wcs == NULL || (cs = calloc(fido_wcslen(wcs) + 1, 1)) == NULL) 
		return NULL;

	for (i = 0; i < fido_wcslen(wcs); i++) {
		if (wcs[i] >= 128) {
			/* give up on parsing non-ASCII text */
			free(cs);
			return strdup("hidapi device");
		}
		cs[i] = (char)wcs[i];
	}

	return cs;
}

static int
copy_info(fido_dev_info_t *di, const struct hid_device_info *d)
{
	memset(di, 0, sizeof(*di));

	if (d->path != NULL)
		di->path = strdup(d->path);
	else
		di->path = strdup("");

	if (d->manufacturer_string != NULL)
		di->manufacturer = wcs_to_cs(d->manufacturer_string);
	else
		di->manufacturer = strdup("");

	if (d->product_string != NULL)
		di->product = wcs_to_cs(d->product_string);
	else
		di->product = strdup("");

	if (di->path == NULL ||
	    di->manufacturer == NULL ||
	    di->product == NULL) {
		free(di->path);
		free(di->manufacturer);
		free(di->product);
		return -1;
	}

	di->product_id = d->product_id;
	di->vendor_id = d->vendor_id;
	di->io = (fido_dev_io_t) {
		&fido_hid_open,
		&fido_hid_close,
		&fido_hid_read,
		&fido_hid_write,
	};

	return 0;
}

void *
fido_hid_open(const char *path)
{
	fido_dev_io_info_t	*io_info;
	void			*hid_dev_handle;

	if ((io_info = malloc(sizeof(*io_info))) == NULL) {
		return (NULL);
	}

	if ((hid_dev_handle = hid_open_path(path)) == NULL) {
		free(io_info);
		return (NULL);
	}

	io_info->io_handle = hid_dev_handle;
	io_info->report_in_len = MAX_CTAP_REPORT_LEN;
	io_info->report_out_len = MAX_CTAP_REPORT_LEN;

	return io_info;
}

void
fido_hid_close(void *opaque_io_info)
{
	fido_dev_io_info_t *io_info = opaque_io_info;

	hid_close(io_info->io_handle);
}

int
fido_hid_read(void *opaque_io_info, unsigned char *buf, size_t len, int ms)
{
	fido_dev_io_info_t *io_info = opaque_io_info;

	return hid_read_timeout(io_info->io_handle, buf, len, ms);
}

int
fido_hid_write(void *opaque_io_info, const unsigned char *buf, size_t len)
{
	fido_dev_io_info_t *io_info = opaque_io_info;

	return hid_write(io_info->io_handle, buf, len);
}

int
fido_hid_manifest(fido_dev_info_t *devlist, size_t ilen, size_t *olen)
{
	struct hid_device_info *hdi;

	*olen = 0;

	if (ilen == 0)
		return FIDO_OK; /* nothing to do */
	if (devlist == NULL)
		return FIDO_ERR_INVALID_ARGUMENT;
	if ((hdi = hid_enumerate(0, 0)) == NULL)
		return FIDO_OK; /* nothing to do */

	for (struct hid_device_info *d = hdi; d != NULL; d = d->next) {
#if defined(_WIN32) || defined(__APPLE__)
		if (d->usage_page != 0xf1d0)
			continue;
#endif
		if (copy_info(&devlist[*olen], d) == 0) {
			if (++(*olen) == ilen)
				break;
		}
	}

	hid_free_enumeration(hdi);

	return FIDO_OK;
}
