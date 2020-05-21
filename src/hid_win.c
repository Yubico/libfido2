/*
 * Copyright (c) 2019 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <sys/types.h>

#include <fcntl.h>
#include <string.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <windows.h>
#include <setupapi.h>
#include <initguid.h>
#include <hidclass.h>
#include <hidsdi.h>

#include "fido.h"

struct hid_win {
	HANDLE dev;
	uint16_t report_in_len;
	uint16_t report_out_len;
};

static bool
is_fido(HANDLE dev)
{
	PHIDP_PREPARSED_DATA data = NULL;
	HIDP_CAPS caps;
	int fido = 0;

	if (HidD_GetPreparsedData(dev, &data) == false) {
		fido_log_debug("%s: HidD_GetPreparsedData", __func__);
		goto fail;
	}

	if (HidP_GetCaps(data, &caps) != HIDP_STATUS_SUCCESS) {
		fido_log_debug("%s: HidP_GetCaps", __func__);
		goto fail;
	}

	fido = (uint16_t)caps.UsagePage == 0xf1d0;
fail:
	if (data != NULL)
		HidD_FreePreparsedData(data);

	return (fido);
}

static int
get_report_len(HANDLE dev, int dir, uint16_t *report_len)
{
	PHIDP_PREPARSED_DATA data = NULL;
	HIDP_CAPS caps;
	USHORT v;
	int ok = -1;

	if (HidD_GetPreparsedData(dev, &data) == false) {
		fido_log_debug("%s: HidD_GetPreparsedData/%d", __func__, dir);
		goto fail;
	}

	if (HidP_GetCaps(data, &caps) != HIDP_STATUS_SUCCESS) {
		fido_log_debug("%s: HidP_GetCaps/%d", __func__, dir);
		goto fail;
	}

	if (dir == 0)
		v = caps.InputReportByteLength;
	else
		v = caps.OutputReportByteLength;

	if (v < CTAP_MIN_REPORT_LEN + 1 || v > CTAP_MAX_REPORT_LEN + 1) {
		fido_log_debug("%s: v/%d=%d", __func__, dir, (int)v);
		goto fail;
	}

	*report_len = (uint16_t)v;

	ok = 0;
fail:
	if (data != NULL)
		HidD_FreePreparsedData(data);

	return (ok);
}

static int
get_int(HANDLE dev, int16_t *vendor_id, int16_t *product_id)
{
	HIDD_ATTRIBUTES attr;

	attr.Size = sizeof(attr);

	if (HidD_GetAttributes(dev, &attr) == false) {
		fido_log_debug("%s: HidD_GetAttributes", __func__);
		return (-1);
	}

	*vendor_id = attr.VendorID;
	*product_id = attr.ProductID;

	return (0);
}

static int
get_str(HANDLE dev, char **manufacturer, char **product)
{
	wchar_t buf[512];
	int utf8_len;
	int ok = -1;

	*manufacturer = NULL;
	*product = NULL;

	if (HidD_GetManufacturerString(dev, &buf, sizeof(buf)) == false) {
		fido_log_debug("%s: HidD_GetManufacturerString", __func__);
		goto fail;
	}

	if ((utf8_len = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, buf,
	    -1, NULL, 0, NULL, NULL)) <= 0 || utf8_len > 128) {
		fido_log_debug("%s: WideCharToMultiByte", __func__);
		goto fail;
	}

	if ((*manufacturer = malloc(utf8_len)) == NULL) {
		fido_log_debug("%s: malloc", __func__);
		goto fail;
	}

	if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, buf, -1,
	    *manufacturer, utf8_len, NULL, NULL) != utf8_len) {
		fido_log_debug("%s: WideCharToMultiByte", __func__);
		goto fail;
	}

	if (HidD_GetProductString(dev, &buf, sizeof(buf)) == false) {
		fido_log_debug("%s: HidD_GetProductString", __func__);
		goto fail;
	}

	if ((utf8_len = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, buf,
	    -1, NULL, 0, NULL, NULL)) <= 0 || utf8_len > 128) {
		fido_log_debug("%s: WideCharToMultiByte", __func__);
		goto fail;
	}

	if ((*product = malloc(utf8_len)) == NULL) {
		fido_log_debug("%s: malloc", __func__);
		goto fail;
	}

	if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, buf, -1,
	    *product, utf8_len, NULL, NULL) != utf8_len) {
		fido_log_debug("%s: WideCharToMultiByte", __func__);
		goto fail;
	}

	ok = 0;
fail:
	if (ok < 0) {
		free(*manufacturer);
		free(*product);
		*manufacturer = NULL;
		*product = NULL;
	}

	return (ok);
}

static int
copy_info(fido_dev_info_t *di, const char *path)
{
	HANDLE dev = INVALID_HANDLE_VALUE;
	int ok = -1;

	memset(di, 0, sizeof(*di));

	dev = CreateFileA(path, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
	    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (dev == INVALID_HANDLE_VALUE || is_fido(dev) == 0)
		goto fail;

	if (get_int(dev, &di->vendor_id, &di->product_id) < 0 ||
	    get_str(dev, &di->manufacturer, &di->product) < 0)
		goto fail;

	if ((di->path = strdup(path)) == NULL)
		goto fail;

	ok = 0;
fail:
	if (dev != INVALID_HANDLE_VALUE)
		CloseHandle(dev);

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
	GUID hid_guid = GUID_DEVINTERFACE_HID;
	HDEVINFO devinfo = INVALID_HANDLE_VALUE;
	SP_DEVICE_INTERFACE_DATA ifdata;
	SP_DEVICE_INTERFACE_DETAIL_DATA_A *ifdetail = NULL;
	DWORD len = 0;
	DWORD idx = 0;
	int r = FIDO_ERR_INTERNAL;

	*olen = 0;

	if (ilen == 0)
		return (FIDO_OK); /* nothing to do */

	if (devlist == NULL)
		return (FIDO_ERR_INVALID_ARGUMENT);

	devinfo = SetupDiGetClassDevsA(&hid_guid, NULL, NULL,
	    DIGCF_DEVICEINTERFACE | DIGCF_PRESENT);
	if (devinfo == INVALID_HANDLE_VALUE) {
		fido_log_debug("%s: SetupDiGetClassDevsA", __func__);
		goto fail;
	}

	ifdata.cbSize = sizeof(SP_DEVICE_INTERFACE_DATA);

	while (SetupDiEnumDeviceInterfaces(devinfo, NULL, &hid_guid, idx++,
	    &ifdata) == true) {
		/*
		 * "Get the required buffer size. Call
		 * SetupDiGetDeviceInterfaceDetail with a NULL
		 * DeviceInterfaceDetailData pointer, a
		 * DeviceInterfaceDetailDataSize of zero, and a valid
		 * RequiredSize variable. In response to such a call, this
		 * function returns the required buffer size at RequiredSize
		 * and fails with GetLastError returning
		 * ERROR_INSUFFICIENT_BUFFER."
		 */
		if (SetupDiGetDeviceInterfaceDetailA(devinfo, &ifdata, NULL, 0,
		    &len, NULL) != false ||
		    GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
			fido_log_debug("%s: SetupDiGetDeviceInterfaceDetailA 1",
			    __func__);
			goto fail;
		}

		if ((ifdetail = malloc(len)) == NULL) {
			fido_log_debug("%s: malloc", __func__);
			goto fail;
		}

		ifdetail->cbSize = sizeof(*ifdetail);

		if (SetupDiGetDeviceInterfaceDetailA(devinfo, &ifdata, ifdetail,
		    len, NULL, NULL) == false) {
			fido_log_debug("%s: SetupDiGetDeviceInterfaceDetailA 2",
			    __func__);
			goto fail;
		}

		if (copy_info(&devlist[*olen], ifdetail->DevicePath) == 0) {
			devlist[*olen].io = (fido_dev_io_t) {
				fido_hid_open,
				fido_hid_close,
				fido_hid_read,
				fido_hid_write,
			};
			if (++(*olen) == ilen)
				break;
		}

		free(ifdetail);
		ifdetail = NULL;
	}

	r = FIDO_OK;
fail:
	if (devinfo != INVALID_HANDLE_VALUE)
		SetupDiDestroyDeviceInfoList(devinfo);

	free(ifdetail);

	return (r);
}

void *
fido_hid_open(const char *path)
{
	struct hid_win *ctx;

	if ((ctx = calloc(1, sizeof(*ctx))) == NULL)
		return (NULL);

	ctx->dev = CreateFileA(path, GENERIC_READ | GENERIC_WRITE,
	    FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
	    FILE_ATTRIBUTE_NORMAL, NULL);

	if (ctx->dev == INVALID_HANDLE_VALUE) {
		free(ctx);
		return (NULL);
	}

	if (get_report_len(ctx->dev, 0, &ctx->report_in_len) < 0 ||
	    get_report_len(ctx->dev, 1, &ctx->report_out_len) < 0) {
		fido_log_debug("%s: get_report_len", __func__);
		fido_hid_close(ctx);
		return (NULL);
	}

	return (ctx);
}

void
fido_hid_close(void *handle)
{
	struct hid_win *ctx = handle;

	CloseHandle(ctx->dev);
	free(ctx);
}

int
fido_hid_read(void *handle, unsigned char *buf, size_t len, int ms)
{
	uint8_t	report[1 + CTAP_MAX_REPORT_LEN];
	struct hid_win *ctx = handle;
	int r = -1;
	DWORD n;

	(void)ms; /* XXX */

	memset(report, 0, sizeof(report));

	if (len != ctx->report_in_len || len > sizeof(report) - 1) {
		fido_log_debug("%s: invalid len", __func__);
		return (-1);
	}

	if (ReadFile(ctx->dev, report, len + 1, &n, NULL) == false ||
	    n != len + 1) {
		fido_log_debug("%s: ReadFile", __func__);
		goto fail;
	}

	/* trim the report id */
	memcpy(buf, report + 1, len);
	r = len;
fail:
	explicit_bzero(report, sizeof(report));

	return (r);
}

int
fido_hid_write(void *handle, const unsigned char *buf, size_t len)
{
	struct hid_win *ctx = handle;
	DWORD n;

	if (len == 0 || len - 1 != ctx->report_out_len) {
		fido_log_debug("%s: invalid len", __func__);
		return (-1);
	}

	if (WriteFile(ctx->dev, buf, (DWORD)len, &n, NULL) == false ||
	    n != len) {
		fido_log_debug("%s: WriteFile", __func__);
		return (-1);
	}

	return (len);
}

uint16_t
fido_hid_report_in_len(void *handle)
{
	struct hid_win *ctx = handle;

	return (ctx->report_in_len);
}

uint16_t
fido_hid_report_out_len(void *handle)
{
	struct hid_win *ctx = handle;

	return (ctx->report_out_len);
}
