/*
 * Copyright (c) 2019 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <sys/types.h>

#include <sys/ioctl.h>
#include <linux/hidraw.h>
#include <linux/input.h>

#include <fcntl.h>
#include <libudev.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "fido.h"

struct ctx_linux {
	int		fd;
	uint16_t	report_in_len;
	uint16_t	report_out_len;
};

static int
get_key_len(uint8_t tag, uint8_t *key, size_t *key_len)
{
	*key = tag & 0xfc;
	if ((*key & 0xf0) == 0xf0) {
		fido_log_debug("%s: *key=0x%02x", __func__, *key);
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
		fido_log_debug("%s: key_len=%zu", __func__, key_len);
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

static void
get_report_lengths(const struct hidraw_report_descriptor *hrd,
    uint16_t *report_in_len, uint16_t *report_out_len)
{
	const uint8_t	*ptr;
	size_t		 len;
	uint16_t	 cur_report_count = 0;

	ptr = hrd->value;
	len = hrd->size;

	*report_in_len = 0;
	*report_out_len = 0;

	while (len > 0) {
		const uint8_t tag = ptr[0];
		ptr++;
		len--;

		uint8_t  key;
		size_t   key_len;
		uint32_t key_val;

		if (get_key_len(tag, &key, &key_len) < 0 || key_len > len ||
		    get_key_val(ptr, key_len, &key_val) < 0) {
			return;
		}

		if (key == 0x94) {
			cur_report_count = key_val;
			fido_log_debug("%s: ReportCount(%d)", __func__, cur_report_count);
		} else if (key == 0x80) {
			*report_in_len = cur_report_count;
			fido_log_debug("%s: Input", __func__);
		} else if (key == 0x90) {
			*report_out_len = cur_report_count;
			fido_log_debug("%s: Output", __func__);
		}

		ptr += key_len;
		len -= key_len;
	}
}

static int
get_report_descriptor(const char *path, struct hidraw_report_descriptor *hrd)
{
	int	s = -1;
	int	fd;
	int	ok = -1;

	if ((fd = open(path, O_RDONLY)) < 0) {
		fido_log_debug("%s: open", __func__);
		return (-1);
	}

	if (ioctl(fd, HIDIOCGRDESCSIZE, &s) < 0 || s < 0 ||
	    (unsigned)s > HID_MAX_DESCRIPTOR_SIZE) {
		fido_log_debug("%s: ioctl HIDIOCGRDESCSIZE", __func__);
		goto fail;
	}

	hrd->size = s;

	if (ioctl(fd, HIDIOCGRDESC, hrd) < 0) {
		fido_log_debug("%s: ioctl HIDIOCGRDESC", __func__);
		goto fail;
	}

	ok = 0;
fail:
	if (fd != -1)
		close(fd);

	return (ok);
}

static bool
is_fido(const char *path)
{
	uint32_t			usage = 0;
	uint32_t			usage_page = 0;
	struct hidraw_report_descriptor	hrd;

	memset(&hrd, 0, sizeof(hrd));

	if (get_report_descriptor(path, &hrd) < 0 ||
	    get_usage_info(&hrd, &usage_page, &usage) < 0) {
		return (false);
	}

	return (usage_page == 0xf1d0);
}

static int
parse_uevent(struct udev_device *dev, uint8_t *bus, int16_t *vendor_id,
    int16_t *product_id, char **product_name)
{
	const char		*uevent;
	char			*cp;
	char			*p;
	char			*s;
	int			 ids_ok = -1;
	int 			 product_name_ok = -1;
	unsigned int		 x;
	short unsigned int	 y;
	short unsigned int	 z;

	*product_name = NULL;

	if ((uevent = udev_device_get_sysattr_value(dev, "uevent")) == NULL)
		return (-1);

	if ((s = cp = strdup(uevent)) == NULL)
		return (-1);

	for ((p = strsep(&cp, "\n")); p && *p != '\0'; (p = strsep(&cp, "\n"))) {
		if (strncmp(p, "HID_ID=", 7) == 0) {
			if (sscanf(p + 7, "%x:%hx:%hx", &x, &y, &z) == 3) {
				*bus = (uint8_t)x;
				*vendor_id = (int16_t)y;
				*product_id = (int16_t)z;
				ids_ok = 0;
			}
		} else if (strncmp(p, "HID_NAME=", 9) == 0) {
			if (*product_name)
				free(*product_name);
			*product_name = strdup(p + 9);
			product_name_ok = 0;
		}
	}

	free(s);

	if (ids_ok != 0 || (*bus == BUS_BLUETOOTH && product_name_ok == -1))
		return (-1);
	else
		return (0);
}

static int
copy_info(fido_dev_info_t *di, struct udev *udev,
    struct udev_list_entry *udev_entry)
{
	const char		*name;
	const char		*path;
	const char		*manufacturer;
	char 			*product_bluetooth = NULL;
	const char		*product_usb;
	struct udev_device	*dev = NULL;
	uint8_t 		 bus;
	struct udev_device	*hid_parent;
	struct udev_device	*usb_parent;
	int			 ok = -1;

	memset(di, 0, sizeof(*di));

	if ((name = udev_list_entry_get_name(udev_entry)) == NULL ||
	    (dev = udev_device_new_from_syspath(udev, name)) == NULL ||
	    (path = udev_device_get_devnode(dev)) == NULL ||
	    is_fido(path) == 0)
		goto fail;

	if ((hid_parent = udev_device_get_parent_with_subsystem_devtype(dev,
	    "hid", NULL)) == NULL)
		goto fail;

	if (parse_uevent(hid_parent, &bus, &di->vendor_id, &di->product_id,
	    &product_bluetooth) < 0)
		goto fail;

	if (bus == BUS_BLUETOOTH) {
		di->manufacturer = strdup("Bluetooth HID");
		di->product = product_bluetooth;
		product_bluetooth = NULL;
	} else {
		if ((usb_parent = udev_device_get_parent_with_subsystem_devtype(
		    dev,"usb", "usb_device")) == NULL)
			goto fail;

		if ((manufacturer = udev_device_get_sysattr_value(usb_parent,
		    "manufacturer")) == NULL || (product_usb =
		    udev_device_get_sysattr_value(usb_parent,"product"))
		    == NULL)
			goto fail;

		di->manufacturer = strdup(manufacturer);
		di->product = strdup(product_usb);
	}

	di->path = strdup(path);

	if (di->path == NULL ||
	    di->manufacturer == NULL ||
	    di->product == NULL)
		goto fail;

	ok = 0;
fail:
	if (dev != NULL)
		udev_device_unref(dev);
	if (product_bluetooth != NULL)
		free(product_bluetooth);

	if (ok < 0) {
		free(di->path);
		free(di->manufacturer);
		free(di->product);
		explicit_bzero(di, sizeof(*di));
	}

	return (ok);
}

int
fido_hid_manifest(fido_dev_info_t *devlist, size_t ilen, size_t *olen)
{
	struct udev		*udev = NULL;
	struct udev_enumerate	*udev_enum = NULL;
	struct udev_list_entry	*udev_list;
	struct udev_list_entry	*udev_entry;
	int			 r = FIDO_ERR_INTERNAL;

	*olen = 0;

	if (ilen == 0)
		return (FIDO_OK); /* nothing to do */

	if (devlist == NULL)
		return (FIDO_ERR_INVALID_ARGUMENT);

	if ((udev = udev_new()) == NULL ||
	    (udev_enum = udev_enumerate_new(udev)) == NULL)
		goto fail;

	if (udev_enumerate_add_match_subsystem(udev_enum, "hidraw") < 0 ||
	    udev_enumerate_scan_devices(udev_enum) < 0)
		goto fail;

	if ((udev_list = udev_enumerate_get_list_entry(udev_enum)) == NULL) {
		r = FIDO_OK; /* zero hidraw devices */
		goto fail;
	}

	udev_list_entry_foreach(udev_entry, udev_list) {
		if (copy_info(&devlist[*olen], udev, udev_entry) == 0) {
			devlist[*olen].io = (fido_dev_io_t) {
				fido_hid_open,
				fido_hid_close,
				fido_hid_read,
				fido_hid_write,
			};
			if (++(*olen) == ilen)
				break;
		}
	}

	r = FIDO_OK;
fail:
	if (udev_enum != NULL)
		udev_enumerate_unref(udev_enum);
	if (udev != NULL)
		udev_unref(udev);

	return (r);
}

void *
fido_hid_open(const char *path)
{
	struct ctx_linux		*ctx;
	struct hidraw_report_descriptor	 hrd;

	if ((ctx = calloc(1, sizeof(*ctx))) == NULL)
		return (NULL);

	if ((ctx->fd = open(path, O_RDWR)) < 0) {
		free(ctx);
		return (NULL);
	}

	ctx->report_in_len = CTAP_MAX_REPORT_LEN;
	ctx->report_out_len = CTAP_MAX_REPORT_LEN;

	/*
	 * Don't fail when report sizes can't be extracted in order to maintain
	 * backwards compatibility.
	 */
	if (get_report_descriptor(path, &hrd) >= 0)
		get_report_lengths(&hrd, &ctx->report_in_len,
		    &ctx->report_out_len);

	return (ctx);
}

void
fido_hid_close(void *handle)
{
	struct ctx_linux *ctx = handle;

	close(ctx->fd);
	free(ctx);
}

int
fido_hid_read(void *handle, unsigned char *buf, size_t len, int ms)
{
	struct ctx_linux *ctx = handle;
	ssize_t	r;

	(void)ms; /* XXX */

	if (len != ctx->report_in_len) {
		fido_log_debug("%s: invalid len %zu/%hu", __func__, len,
		    ctx->report_in_len);
		return (-1);
	}

	if ((r = read(ctx->fd, buf, len)) < 0 ||
	    (size_t)r != ctx->report_in_len) {
		fido_log_debug("%s: read", __func__);
		return (-1);
	}

	return ((int)r);
}

int
fido_hid_write(void *handle, const unsigned char *buf, size_t len)
{
	struct ctx_linux *ctx = handle;
	ssize_t r;

	if (len != ctx->report_out_len + 1u) {
		fido_log_debug("%s: invalid len %zu/%hu", __func__, len,
		    ctx->report_out_len);
		return (-1);
	}

	if ((r = write(ctx->fd, buf, len)) < 0 ||
	    (size_t)r != ctx->report_out_len + 1u) {
		fido_log_debug("%s: write", __func__);
		return (-1);
	}

	return ((int)r);
}

uint16_t
fido_hid_report_in_len(void *handle)
{
	struct ctx_linux *ctx = handle;

	return (ctx->report_in_len);
}

uint16_t
fido_hid_report_out_len(void *handle)
{
	struct ctx_linux *ctx = handle;

	return (ctx->report_out_len);
}
