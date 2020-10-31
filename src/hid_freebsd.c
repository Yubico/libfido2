/*
 * Copyright (c) 2020 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <sys/types.h>

#include <dev/usb/usb_ioctl.h>
#include <dev/usb/usbhid.h>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <string.h>
#include <unistd.h>

#include "fido.h"

#define MAX_UHID	64

struct hid_freebsd {
	int	fd;
	size_t	report_in_len;
	size_t	report_out_len;
};

static bool
is_fido(int fd)
{
	char				buf[64];
	struct usb_gen_descriptor	ugd;
	uint32_t			usage_page = 0;

	memset(&buf, 0, sizeof(buf));
	memset(&ugd, 0, sizeof(ugd));

	ugd.ugd_report_type = UHID_FEATURE_REPORT;
	ugd.ugd_data = buf;
	ugd.ugd_maxlen = sizeof(buf);

	if (ioctl(fd, USB_GET_REPORT_DESC, &ugd) == -1) {
		fido_log_debug("%s: ioctl", __func__);
		return (false);
	}

	if (ugd.ugd_actlen > sizeof(buf) ||
	    fido_hid_get_usage(ugd.ugd_data, ugd.ugd_actlen, &usage_page) < 0) {
		fido_log_debug("%s: fido_hid_get_usage", __func__);
		return (false);
	}

	return (usage_page == 0xf1d0);
}

static int
copy_info(fido_dev_info_t *di, const char *path)
{
	int			fd = -1;
	int			ok = -1;
	struct usb_device_info	udi;

	memset(di, 0, sizeof(*di));
	memset(&udi, 0, sizeof(udi));

	if ((fd = open(path, O_RDWR)) == -1) {
		if (errno != ENOENT && errno != ENXIO)
			fido_log_debug("%s: open %s: %s", __func__,
			    path, strerror(errno));
		goto fail;
	}

	if (is_fido(fd) == 0)
		goto fail;

	if (ioctl(fd, USB_GET_DEVICEINFO, &udi) == -1) {
		strlcpy(udi.udi_vendor, "FreeBSD", sizeof(udi.udi_vendor));
		strlcpy(udi.udi_product, "uhid(4)", sizeof(udi.udi_product));
		udi.udi_vendorNo = 0x0b5d; /* stolen from PCI_VENDOR_OPENBSD */
	}

	if ((di->path = strdup(path)) == NULL ||
	    (di->manufacturer = strdup(udi.udi_vendor)) == NULL ||
	    (di->product = strdup(udi.udi_product)) == NULL)
		goto fail;

	di->vendor_id = (int16_t)udi.udi_vendorNo;
	di->product_id = (int16_t)udi.udi_productNo;

	ok = 0;
fail:
	if (fd != -1)
		close(fd);

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
	char	path[64];
	size_t	i;

	*olen = 0;

	if (ilen == 0)
		return (FIDO_OK); /* nothing to do */

	if (devlist == NULL || olen == NULL)
		return (FIDO_ERR_INVALID_ARGUMENT);

	for (i = *olen = 0; i < MAX_UHID && *olen < ilen; i++) {
		snprintf(path, sizeof(path), "/dev/uhid%zu", i);
		if (copy_info(&devlist[*olen], path) == 0) {
			devlist[*olen].io = (fido_dev_io_t) {
				fido_hid_open,
				fido_hid_close,
				fido_hid_read,
				fido_hid_write,
			};
			++(*olen);
		}
	}

	return (FIDO_OK);
}

void *
fido_hid_open(const char *path)
{
	char				 buf[64];
	struct hid_freebsd		*ctx;
	struct usb_gen_descriptor	 ugd;

	memset(&buf, 0, sizeof(buf));
	memset(&ugd, 0, sizeof(ugd));

	if ((ctx = calloc(1, sizeof(*ctx))) == NULL)
		return (NULL);

	if ((ctx->fd = open(path, O_RDWR)) < 0) {
		free(ctx);
		return (NULL);
	}

	ugd.ugd_report_type = UHID_FEATURE_REPORT;
	ugd.ugd_data = buf;
	ugd.ugd_maxlen = sizeof(buf);

	if (ioctl(ctx->fd, USB_GET_REPORT_DESC, &ugd) == -1 ||
	    ugd.ugd_actlen > sizeof(buf) ||
	    fido_hid_get_report_len(ugd.ugd_data, ugd.ugd_actlen,
	    &ctx->report_in_len, &ctx->report_out_len) < 0) {
		fido_log_debug("%s: using default report sizes", __func__);
		ctx->report_in_len = CTAP_MAX_REPORT_LEN;
		ctx->report_out_len = CTAP_MAX_REPORT_LEN;
	}

	return (ctx);
}

void
fido_hid_close(void *handle)
{
	struct hid_freebsd *ctx = handle;

	close(ctx->fd);
	free(ctx);
}

static int
timespec_to_ms(const struct timespec *ts, int upper_bound)
{
	int64_t x;
	int64_t y;

	if (ts->tv_sec < 0 || (uint64_t)ts->tv_sec > INT64_MAX / 1000LL ||
	    ts->tv_nsec < 0 || (uint64_t)ts->tv_nsec / 1000000LL > INT64_MAX)
		return (upper_bound);

	x = ts->tv_sec * 1000LL;
	y = ts->tv_nsec / 1000000LL;

	if (INT64_MAX - x < y || x + y > upper_bound)
		return (upper_bound);

	return (int)(x + y);
}

static int
waitfd(int fd, int ms)
{
	struct timespec	ts_start;
	struct timespec	ts_now;
	struct timespec	ts_delta;
	struct pollfd	pfd;
	int		ms_remain;
	int		r;

	if (ms < 0)
		return (0);

	memset(&pfd, 0, sizeof(pfd));
	pfd.events = POLLIN;
	pfd.fd = fd;

	if (clock_gettime(CLOCK_MONOTONIC, &ts_start) != 0) {
		fido_log_debug("%s: clock_gettime: %s", __func__,
		    strerror(errno));
		return (-1);
	}

	for (ms_remain = ms; ms_remain > 0;) {
		if ((r = poll(&pfd, 1, ms_remain)) > 0)
			return (0);
		else if (r == 0)
			break;
		else if (errno != EINTR) {
			fido_log_debug("%s: poll: %s", __func__,
			    strerror(errno));
			return (-1);
		}
		/* poll interrupted - subtract time already waited */
		if (clock_gettime(CLOCK_MONOTONIC, &ts_now) != 0) {
			fido_log_debug("%s: clock_gettime: %s", __func__,
			    strerror(errno));
			return (-1);
		}
		timespecsub(&ts_now, &ts_start, &ts_delta);
		ms_remain = ms - timespec_to_ms(&ts_delta, ms);
	}

	return (-1);
}

int
fido_hid_read(void *handle, unsigned char *buf, size_t len, int ms)
{
	struct hid_freebsd	*ctx = handle;
	ssize_t			 r;

	if (len != ctx->report_in_len) {
		fido_log_debug("%s: len %zu", __func__, len);
		return (-1);
	}

	if (waitfd(ctx->fd, ms) < 0) {
		fido_log_debug("%s: fd not ready", __func__);
		return (-1);
	}

	if ((r = read(ctx->fd, buf, len)) == -1 || (size_t)r != len) {
		fido_log_debug("%s: read", __func__);
		return (-1);
	}

	return ((int)r);
}

int
fido_hid_write(void *handle, const unsigned char *buf, size_t len)
{
	struct hid_freebsd	*ctx = handle;
	ssize_t			 r;

	if (len != ctx->report_out_len + 1) {
		fido_log_debug("%s: len %zu", __func__, len);
		return (-1);
	}

	if ((r = write(ctx->fd, buf + 1, len - 1)) == -1 ||
	    (size_t)r != len - 1) {
		fido_log_debug("%s: write", __func__);
		return (-1);
	}

	return ((int)len);
}

size_t
fido_hid_report_in_len(void *handle)
{
	struct hid_freebsd *ctx = handle;

	return (ctx->report_in_len);
}

size_t
fido_hid_report_out_len(void *handle)
{
	struct hid_freebsd *ctx = handle;

	return (ctx->report_out_len);
}
