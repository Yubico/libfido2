/*
 * Copyright (c) 2022 Micro Focus or one of its affiliates.
 * Copyright (c) 2022 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#if __APPLE__
#include <PCSC/wintypes.h>
#include <PCSC/winscard.h>
#else
#include <winscard.h>
#endif /* __APPLE__ */

#include "fido.h"
#include "fido/param.h"
#include "iso7816.h"

#if defined(_WIN32) && !defined(__MINGW32__)
#define SCardConnect SCardConnectA
#define SCardListReaders SCardListReadersA
#endif

#ifndef SCARD_PROTOCOL_Tx
#define SCARD_PROTOCOL_Tx SCARD_PROTOCOL_ANY
#endif

struct pcsc {
	SCARDCONTEXT     ctx;
	SCARDHANDLE      h;
	SCARD_IO_REQUEST req;
	uint8_t          rx_buf[FIDO_MAXMSG];
	size_t           rx_len;
};

static char *
get_reader(const char *path)
{
	char *o = NULL, *p;
	char *reader = NULL;
	const char prefix[] = FIDO_PCSC_PREFIX "{";

	if (path == NULL)
		goto out;
	if ((o = p = strdup(path)) == NULL ||
	    strncmp(p, prefix, strlen(prefix)) != 0)
		goto out;
	p += strlen(prefix);
	if (strlen(p) == 0 || p[strlen(p) - 1] != '}')
		goto out;
	p[strlen(p) - 1] = '\0';
	reader = strdup(p);
out:
	free(o);

	return reader;
}

static int
prepare_io_request(DWORD prot, SCARD_IO_REQUEST *req)
{
	switch (prot) {
	case SCARD_PROTOCOL_T0:
		req->dwProtocol = SCARD_PCI_T0->dwProtocol;
		req->cbPciLength = SCARD_PCI_T0->cbPciLength;
		break;
	case SCARD_PROTOCOL_T1:
		req->dwProtocol = SCARD_PCI_T1->dwProtocol;
		req->cbPciLength = SCARD_PCI_T1->cbPciLength;
		break;
	default:
		fido_log_debug("%s: unknown protocol %lu", __func__,
		    (u_long)prot);
		return -1;
	}

	return 0;
}

static int
copy_info(fido_dev_info_t *di, SCARDCONTEXT ctx, const char *reader)
{
	SCARDHANDLE h = 0;
	SCARD_IO_REQUEST req;
	DWORD prot = 0;
	LONG s;
	char path[512];
	int r, ok = -1;

	memset(di, 0, sizeof(*di));
	memset(&req, 0, sizeof(req));

	if ((s = SCardConnect(ctx, reader, SCARD_SHARE_SHARED,
	    SCARD_PROTOCOL_Tx, &h, &prot)) != SCARD_S_SUCCESS) {
		fido_log_debug("%s: SCardConnect 0x%lx", __func__, (long)s);
		goto fail;
	}
	if (prepare_io_request(prot, &req) < 0) {
		fido_log_debug("%s: prepare_io_request", __func__);
		goto fail;
	}
	if ((r = snprintf(path, sizeof(path), "%s{%s}", FIDO_PCSC_PREFIX,
	    reader)) < 0 || (size_t)r >= sizeof(path)) {
		fido_log_debug("%s: snprintf", __func__);
		goto fail;
	}
	di->path = strdup(path);
	di->manufacturer = strdup("PC/SC");
	di->product = strdup(reader);
	if (di->path == NULL || di->manufacturer == NULL || di->product == NULL)
		goto fail;

	ok = 0;
fail:
	if (h != 0)
		SCardDisconnect(h, SCARD_LEAVE_CARD);
	if (ok < 0) {
		free(di->path);
		free(di->manufacturer);
		free(di->product);
		explicit_bzero(di, sizeof(*di));
	}

	return ok;
}

int
fido_pcsc_manifest(fido_dev_info_t *devlist, size_t ilen, size_t *olen)
{
	SCARDCONTEXT ctx = 0;
	char *buf = NULL;
	const char *reader;
	DWORD len;
	LONG s;
	int r = FIDO_ERR_INTERNAL;

	*olen = 0;

	if (ilen == 0)
		return FIDO_OK;
	if (devlist == NULL)
		return FIDO_ERR_INVALID_ARGUMENT;

	if ((s = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL,
	    &ctx)) != SCARD_S_SUCCESS || ctx == 0) {
		fido_log_debug("%s: SCardEstablishContext 0x%lx", __func__,
		    (long)s);
		if (s == (LONG)SCARD_E_NO_SERVICE ||
		    s == (LONG)SCARD_E_NO_SMARTCARD)
			r = FIDO_OK; /* suppress error */
		goto out;
	}
	len = 1024; /* XXX */
	if ((buf = calloc(1, len)) == NULL)
		goto out;
	if ((s = SCardListReaders(ctx, NULL, buf,
	    &len)) != SCARD_S_SUCCESS || buf == NULL) {
		fido_log_debug("%s: SCardListReaders 0x%lx", __func__, (long)s);
		if (s == (LONG)SCARD_E_NO_READERS_AVAILABLE)
			r = FIDO_OK; /* suppress error */
		goto out;
	}
	/* sanity check "multi-string" */
	if (len < 2 || buf[len - 1] != 0 || buf[len - 2] != '\0') {
		fido_log_debug("%s: can't parse buf returned by "
		    "SCardListReaders", __func__);
		goto out;
	}

	for (reader = buf; *reader != 0; reader += strlen(reader) + 1) {
		if (copy_info(&devlist[*olen], ctx, reader) == 0) {
			devlist[*olen].io = (fido_dev_io_t) {
				fido_pcsc_open,
				fido_pcsc_close,
				fido_pcsc_read,
				fido_pcsc_write,
			};
			devlist[*olen].transport = (fido_dev_transport_t) {
				fido_pcsc_rx,
				fido_pcsc_tx,
			};
			if (++(*olen) == ilen)
				break;
		}
	}

	r = FIDO_OK;
out:
	free(buf);
	if (ctx != 0)
		SCardReleaseContext(ctx);

	return r;
}

void *
fido_pcsc_open(const char *path)
{
	char *reader;
	struct pcsc *dev = NULL;
	SCARDCONTEXT ctx = 0;
	SCARDHANDLE h = 0;
	SCARD_IO_REQUEST req;
	DWORD prot = 0;
	LONG s;

	memset(&req, 0, sizeof(req));

	if ((reader = get_reader(path)) == NULL) {
		fido_log_debug("%s: get_reader(%s)", __func__, path);
		goto fail;
	}
	if ((s = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL,
	    &ctx)) != SCARD_S_SUCCESS || ctx == 0) {
		fido_log_debug("%s: SCardEstablishContext 0x%lx", __func__,
		    (long)s);
		goto fail;

	}
	if ((s = SCardConnect(ctx, reader, SCARD_SHARE_SHARED,
	    SCARD_PROTOCOL_Tx, &h, &prot)) != SCARD_S_SUCCESS) {
		fido_log_debug("%s: SCardConnect 0x%lx", __func__, (long)s);
		goto fail;
	}
	if (prepare_io_request(prot, &req) < 0) {
		fido_log_debug("%s: prepare_io_request", __func__);
		goto fail;
	}
	if ((dev = calloc(1, sizeof(*dev))) == NULL)
		goto fail;

	dev->ctx = ctx;
	dev->h = h;
	dev->req = req;
	ctx = 0;
	h = 0;
fail:
	if (h != 0)
		SCardDisconnect(h, SCARD_LEAVE_CARD);
	if (ctx != 0)
		SCardReleaseContext(ctx);
	free(reader);

	return dev;
}

void
fido_pcsc_close(void *handle)
{
	struct pcsc *dev = handle;

	if (dev->h != 0)
		SCardDisconnect(dev->h, SCARD_LEAVE_CARD);
	if (dev->ctx != 0)
		SCardReleaseContext(dev->ctx);

	explicit_bzero(dev->rx_buf, sizeof(dev->rx_buf));
	free(dev);
}

int
fido_pcsc_read(void *handle, unsigned char *buf, size_t len, int ms)
{
	struct pcsc *dev = handle;
	int r;

	(void)ms;
	if (dev->rx_len == 0 || dev->rx_len > len ||
	    dev->rx_len > sizeof(dev->rx_buf)) {
		fido_log_debug("%s: rx_len", __func__);
		return -1;
	}
	fido_log_xxd(dev->rx_buf, dev->rx_len, "%s: reading", __func__);
	memcpy(buf, dev->rx_buf, dev->rx_len);
	explicit_bzero(dev->rx_buf, sizeof(dev->rx_buf));
	r = (int)dev->rx_len;
	dev->rx_len = 0;

	return r;
}

int
fido_pcsc_write(void *handle, const unsigned char *buf, size_t len)
{
	struct pcsc *dev = handle;
	DWORD n;
	LONG s;

	if (len > INT_MAX) {
		fido_log_debug("%s: len", __func__);
		return -1;
	}
	if (dev->rx_len) {
		fido_log_xxd(dev->rx_buf, dev->rx_len, "%s: dropping %zu bytes "
		    "from input buffer", __func__, dev->rx_len);
	}
	explicit_bzero(dev->rx_buf, sizeof(dev->rx_buf));
	dev->rx_len = 0;
	n = (DWORD)sizeof(dev->rx_buf);
	fido_log_xxd(buf, len, "%s: writing", __func__);
	if ((s = SCardTransmit(dev->h, &dev->req, buf, (DWORD)len, NULL,
	    dev->rx_buf, &n)) != SCARD_S_SUCCESS) {
		fido_log_debug("%s: SCardTransmit 0x%lx", __func__, (long)s);
		explicit_bzero(dev->rx_buf, sizeof(dev->rx_buf));
		return -1;
	}
	dev->rx_len = (size_t)n;
	fido_log_xxd(dev->rx_buf, dev->rx_len, "%s: read", __func__);

	return (int)len;
}

int
fido_pcsc_tx(fido_dev_t *d, uint8_t cmd, const u_char *buf, size_t count)
{
	return fido_nfc_tx(d, cmd, buf, count);
}

int
fido_pcsc_rx(fido_dev_t *d, uint8_t cmd, u_char *buf, size_t count, int ms)
{
	return fido_nfc_rx(d, cmd, buf, count, ms);
}

bool
fido_is_pcsc(const char *path)
{
	return strncmp(path, FIDO_PCSC_PREFIX, strlen(FIDO_PCSC_PREFIX)) == 0;
}

int
fido_dev_set_pcsc(fido_dev_t *d)
{
	if (d->io_handle != NULL) {
		fido_log_debug("%s: device open", __func__);
		return -1;
	}
	d->io_own = true;
	d->io = (fido_dev_io_t) {
		fido_pcsc_open,
		fido_pcsc_close,
		fido_pcsc_read,
		fido_pcsc_write,
	};
	d->transport = (fido_dev_transport_t) {
		fido_pcsc_rx,
		fido_pcsc_tx,
	};

	return 0;
}
