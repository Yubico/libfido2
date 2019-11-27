/*
 * Copyright (c) 2018 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "fido.h"

/* CTAP section 8.1.4 */
enum {
	CID,

	INIT_CMD = 4,
	INIT_BCNTH,
	INIT_BCNTL,
	INIT_DATA,

	CONT_SEQ = 4,
	CONT_DATA,
};

#ifndef MIN
#define MIN(x, y) ((x) > (y) ? (y) : (x))
#endif

static size_t
tx_preamble(fido_dev_t *d,  uint8_t cmd, const void *buf, size_t count)
{
	uint8_t	pkt[1 + CTAP_RPT_SIZE] = {0};
	int	n;

	if (d->io.write == NULL || (cmd & 0x80) == 0)
		return (0);

	memcpy(&pkt[1], &d->cid, 4);
	pkt[1 + INIT_CMD] = 0x80 | cmd;
	pkt[1 + INIT_BCNTH] = (count >> 8) & 0xff;
	pkt[1 + INIT_BCNTL] = count & 0xff;
	count = MIN(count, CTAP_RPT_SIZE - INIT_DATA);
	if (count)
		memcpy(&pkt[1 + INIT_DATA], buf, count);

	n = d->io.write(d->io_handle, pkt, sizeof(pkt));
	if (n < 0 || (size_t)n != sizeof(pkt))
		return (0);

	return (count);
}

static size_t
tx_frame(fido_dev_t *d, int seq, const void *buf, size_t count)
{
	uint8_t	pkt[1 + CTAP_RPT_SIZE] = {0};
	int	n;

	if (d->io.write == NULL || seq < 0 || seq > UINT8_MAX)
		return (0);

	memcpy(&pkt[1], &d->cid, 4);
	pkt[1 + CONT_SEQ] = seq;
	count = MIN(count, CTAP_RPT_SIZE - CONT_DATA);
	memcpy(&pkt[1 + CONT_DATA], buf, count);

	n = d->io.write(d->io_handle, pkt, sizeof(pkt));
	if (n < 0 || (size_t)n != sizeof(pkt))
		return (0);

	return (count);
}

int
fido_tx(fido_dev_t *d, uint8_t cmd, const void *buf, size_t count)
{
	int	seq = 0;
	size_t	sent;

	fido_log_debug("%s: d=%p, cmd=0x%02x, buf=%p, count=%zu", __func__,
	    (void *)d, cmd, buf, count);
	fido_log_xxd(buf, count);

	if (d->io_handle == NULL || count > UINT16_MAX) {
		fido_log_debug("%s: invalid argument (%p, %zu)", __func__,
		    d->io_handle, count);
		return (-1);
	}

	if ((sent = tx_preamble(d, cmd, buf, count)) == 0) {
		fido_log_debug("%s: tx_preamble", __func__);
		return (-1);
	}

	while (sent < count) {
		if (seq & 0x80) {
			fido_log_debug("%s: seq & 0x80", __func__);
			return (-1);
		}
		const uint8_t *p = (const uint8_t *)buf + sent;
		size_t n = tx_frame(d, seq++, p, count - sent);
		if (n == 0) {
			fido_log_debug("%s: tx_frame", __func__);
			return (-1);
		}
		sent += n;
	}

	return (0);
}

static int
rx_frame(fido_dev_t *d, uint8_t *fp, int ms)
{
	int n;

	if (d->io.read == NULL)
		return (-1);

	n = d->io.read(d->io_handle, (unsigned char *)fp, CTAP_RPT_SIZE, ms);
	if (n < 0 || (size_t)n != CTAP_RPT_SIZE)
		return (-1);

	return (0);
}

static int
rx_preamble(fido_dev_t *d, uint8_t *fp, int ms)
{
	uint32_t cid;

	do {
		if (rx_frame(d, fp, ms) < 0)
			return (-1);
		memcpy(&cid, &fp[CID], 4);
#ifdef FIDO_FUZZ
		cid = d->cid;
#endif
	} while (cid == d->cid &&
	    fp[INIT_CMD] == (CTAP_FRAME_INIT | CTAP_KEEPALIVE));

	return (0);
}

int
fido_rx(fido_dev_t *d, uint8_t cmd, void *buf, size_t count, int ms)
{
	uint8_t		f[CTAP_RPT_SIZE];
	uint32_t	cid;
	uint16_t	r;
	uint16_t	flen;
	int		seq;

	if (d->io_handle == NULL || (cmd & 0x80) == 0) {
		fido_log_debug("%s: invalid argument (%p, 0x%02x)", __func__,
		    d->io_handle, cmd);
		return (-1);
	}

	if (rx_preamble(d, f, ms) < 0) {
		fido_log_debug("%s: rx_preamble", __func__);
		return (-1);
	}

	fido_log_debug("%s: initiation frame at %p, len %zu", __func__,
	    (void *)&f, sizeof(f));
	fido_log_xxd(&f, sizeof(f));

	memcpy(&cid, &f[CID], 4);

#ifdef FIDO_FUZZ
	cid = d->cid;
	f[INIT_CMD] = cmd;
#endif

	if (cid != d->cid || f[INIT_CMD] != cmd) {
		fido_log_debug("%s: cid (0x%x, 0x%x), cmd (0x%02x, 0x%02x)",
		    __func__, cid, d->cid, f[INIT_CMD], cmd);
		return (-1);
	}

	flen = (f[INIT_BCNTH] << 8) | f[INIT_BCNTL];
	if (count < (size_t)flen) {
		fido_log_debug("%s: count < flen (%zu, %zu)", __func__, count,
		    (size_t)flen);
		return (-1);
	}
	if (flen < CTAP_RPT_SIZE - INIT_DATA) {
		memcpy(buf, &f[INIT_DATA], flen);
		return (flen);
	}

	memcpy(buf, &f[INIT_DATA], CTAP_RPT_SIZE - INIT_DATA);
	r = CTAP_RPT_SIZE - INIT_DATA;
	seq = 0;

	while ((size_t)r < flen) {
		if (rx_frame(d, f, ms) < 0) {
			fido_log_debug("%s: rx_frame", __func__);
			return (-1);
		}

		fido_log_debug("%s: continuation frame at %p, len %zu",
		    __func__, (void *)&f, sizeof(f));
		fido_log_xxd(&f, sizeof(f));

		memcpy(&cid, &f[CID], 4);

#ifdef FIDO_FUZZ
		cid = d->cid;
		f[CONT_SEQ] = seq;
#endif

		if (cid != d->cid || f[CONT_SEQ] != seq++) {
			fido_log_debug("%s: cid (0x%x, 0x%x), seq (%d, %d)",
			    __func__, cid, d->cid, f[CONT_SEQ], seq);
			return (-1);
		}

		uint8_t *p = (uint8_t *)buf + r;

		if ((size_t)(flen - r) > CTAP_RPT_SIZE - CONT_DATA) {
			memcpy(p, &f[CONT_DATA], CTAP_RPT_SIZE - CONT_DATA);
			r += CTAP_RPT_SIZE - CONT_DATA;
		} else {
			memcpy(p, &f[CONT_DATA], flen - r);
			r += (flen - r); /* break */
		}
	}

	fido_log_debug("%s: payload at %p, len %zu", __func__, buf, (size_t)r);
	fido_log_xxd(buf, r);

	return (r);
}

int
fido_rx_cbor_status(fido_dev_t *d, int ms)
{
	const uint8_t	cmd = CTAP_FRAME_INIT | CTAP_CMD_CBOR;
	unsigned char	reply[2048];
	int		reply_len;

	if ((reply_len = fido_rx(d, cmd, &reply, sizeof(reply), ms)) < 0 ||
	    (size_t)reply_len < 1) {
		fido_log_debug("%s: fido_rx", __func__);
		return (FIDO_ERR_RX);
	}

	return (reply[0]);
}
