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
	if (wcs == NULL)
		return NULL;
	char *cs;
	size_t i;
	cs = calloc(fido_wcslen(wcs) + 1, 1);
	if (cs == NULL)
		return NULL;
	for (i = 0; i < fido_wcslen(wcs); i++) {
		if (wcs[i] >= 128) {
			// give up on parsing non-ASCII text
			free(cs);
			cs = strdup("hidapi device");
			return cs;
		}
		cs[i] = (char) wcs[i];
	}
	return cs;
}

static int
copy_info(fido_dev_info_t *fido_dev_info,
    const struct hid_device_info *hid_dev_info)
{
	if (hid_dev_info->path != NULL) {
		fido_dev_info->path = strdup(hid_dev_info->path);
	} else {
		fido_dev_info->path = strdup("");
	}
	if (fido_dev_info->path == NULL)
		goto finish;
	if (hid_dev_info->manufacturer_string != NULL) {
		fido_dev_info->manufacturer = wcs_to_cs(hid_dev_info->manufacturer_string);
	} else {
		fido_dev_info->manufacturer = strdup("");
	}
	if (fido_dev_info->manufacturer == NULL)
		goto finish;
	if (hid_dev_info->product_string != NULL) {
		fido_dev_info->product = wcs_to_cs(hid_dev_info->product_string);
	} else {
		fido_dev_info->product = strdup("");
	}
	if (fido_dev_info->product == NULL)
		goto finish;
	fido_dev_info->product_id = hid_dev_info->product_id;
	fido_dev_info->vendor_id = hid_dev_info->vendor_id;
finish:
	if (fido_dev_info->path == NULL ||
	    fido_dev_info->manufacturer == NULL ||
	    fido_dev_info->product == NULL) {
		free(fido_dev_info->path);
		free(fido_dev_info->manufacturer);
		free(fido_dev_info->product);
		return -1;
	}
	return 0;
}

void *
fido_hid_open(const char *path)
{
	return hid_open_path(path);
}

void
fido_hid_close(void *hid_dev_handle)
{
	hid_close(hid_dev_handle);
}

int
fido_hid_read(void *hid_dev_handle, unsigned char *buf, size_t len, int ms)
{
	return hid_read_timeout(hid_dev_handle, buf, len, ms);
}

int
fido_hid_write(void *hid_dev_handle, const unsigned char *buf, size_t len)
{
	return hid_write(hid_dev_handle, buf, len);
}

int
fido_hid_manifest(fido_dev_info_t *dev_infos, size_t ilen, size_t *olen)
{
	struct hid_device_info *hid_devs = hid_enumerate(0, 0);
	*olen = 0;
	if (hid_devs != NULL) {
		struct hid_device_info *curr_hid_dev = hid_devs;
		while (curr_hid_dev != NULL && *olen < ilen) {
			fido_dev_info_t *curr_dev_info = &dev_infos[*olen];
			if (copy_info(curr_dev_info, curr_hid_dev) != 0)
				break;
			curr_dev_info->io = (fido_dev_io_t) {
				&fido_hid_open,
				&fido_hid_close,
				&fido_hid_read,
				&fido_hid_write
			};
			(*olen)++;
			curr_hid_dev = curr_hid_dev->next;
		}
		hid_free_enumeration(hid_devs);
	}
	return (FIDO_OK);
}
