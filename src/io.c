/*
 * Copyright (c) 2018 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <hidapi.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "fido.h"

struct frame {
	uint32_t cid; /* channel id */
	union {
		uint8_t type;
		struct {
			uint8_t cmd;
			uint8_t bcnth;
			uint8_t bcntl;
			uint8_t data[CTAP_RPT_SIZE - 7];
		} init;
		struct {
			uint8_t seq;
			uint8_t data[CTAP_RPT_SIZE - 5];
		} cont;
	} body;
};

#ifndef MIN
#define MIN(x, y) ((x) > (y) ? (y) : (x))
#endif

#define LOG_BUF(l, p, n) do {					\
	if (debug) {						\
		fprintf(stderr, "[%s] %s:\n", __func__, (l));	\
		xxd((p), (n));					\
	}							\
} while (0)

#define LOG_RET(x) do {						\
	int y = (x); /* evaluate x only once */			\
	if (debug) {						\
		fprintf(stderr, "[%s] returning %d in line "	\
		    "%u\n", __func__, (y), __LINE__);		\
	}							\
	return ((y));						\
} while (0)

static void
xxd(const void *buf, size_t count)
{
	const uint8_t *ptr = buf;

	while (count--)
		fprintf(stderr, "%02x", *ptr++);

	fprintf(stderr, "\n");
}

static size_t
tx_preamble(fido_dev_t *d,  uint8_t cmd, const void *buf, size_t count)
{
	struct frame	*fp;
	unsigned char	pkt[sizeof(*fp) + 1];
	int		n;

	if ((cmd & 0x80) == 0)
		return (-1);

	memset(&pkt, 0, sizeof(pkt));
	fp = (struct frame *)(pkt + 1);
	fp->cid = fido_dev_cid(d);
	fp->body.init.cmd = 0x80 | cmd;
	fp->body.init.bcnth = (count >> 8) & 0xff;
	fp->body.init.bcntl = count & 0xff;
	count = MIN(count, sizeof(fp->body.init.data));
	memcpy(&fp->body.init.data, buf, count);

	n = hid_write(fido_dev_hid(d), pkt, sizeof(pkt));
	if (n < 0 || (size_t)n != sizeof(pkt))
		return (0);

	return (count);
}

static size_t
tx_frame(fido_dev_t *d, int seq, const void *buf, size_t count)
{
	struct frame	*fp;
	unsigned char	 pkt[sizeof(*fp) + 1];
	int		 n;

	memset(&pkt, 0, sizeof(pkt));
	fp = (struct frame *)(pkt + 1);
	fp->cid = fido_dev_cid(d);
	fp->body.cont.seq = seq++;
	count = MIN(count, sizeof(fp->body.cont.data));
	memcpy(&fp->body.cont.data, buf, count);

	n = hid_write(fido_dev_hid(d), pkt, sizeof(pkt));
	if (n < 0 || (size_t)n != sizeof(pkt))
		return (0);

	return (count);
}

int
tx(fido_dev_t *d, uint8_t cmd, const void *buf, size_t count)
{
	int	seq = 0;
	size_t	sent;

	LOG_BUF("payload", buf, count);

	if (fido_dev_hid(d) == NULL || count > UINT16_MAX ||
	    (sent = tx_preamble(d, cmd, buf, count)) == 0)
		LOG_RET(-1);

	while (sent < count) {
		if (seq & 0x80)
			LOG_RET(-1);
		const uint8_t *p = (const uint8_t *)buf + sent;
		size_t n = tx_frame(d, seq++, p, count - sent);
		if (n == 0)
			LOG_RET(-1);
		sent += n;
	}

	LOG_RET(0);
}

static int
rx_frame(fido_dev_t *d, struct frame *fp, int ms)
{
	int n;

	n = hid_read_timeout(fido_dev_hid(d), (unsigned char *)fp,
	    sizeof(*fp), ms);
	if (n < 0 || (size_t)n != sizeof(*fp))
		return (-1);

	return (0);
}

static int
rx_preamble(fido_dev_t *d, struct frame *fp, int ms)
{
	do {
		if (rx_frame(d, fp, ms) < 0)
			return (-1);
	} while (fp->cid == fido_dev_cid(d) &&
	    fp->body.init.cmd == (CTAP_FRAME_INIT | CTAP_KEEPALIVE));

	return (0);
}

int
rx(fido_dev_t *d, uint8_t cmd, void *buf, size_t count, int ms)
{
	struct frame	f;
	uint16_t	r;
	uint16_t	flen;
	int		seq;

	if (fido_dev_hid(d) == NULL || (cmd & 0x80) == 0)
		LOG_RET(-1);
	if (rx_preamble(d, &f, ms) < 0)
		LOG_RET(-1);

	LOG_BUF("initiation frame", (void *)&f, sizeof(f));

	if (f.cid != fido_dev_cid(d) || f.body.init.cmd != cmd)
		LOG_RET(-1);

	flen = (f.body.init.bcnth << 8) | f.body.init.bcntl;
	if (count < (size_t)flen)
		LOG_RET(-1);
	if (flen < sizeof(f.body.init.data)) {
		memcpy(buf, f.body.init.data, flen);
		LOG_RET(flen);
	}

	memcpy(buf, f.body.init.data, sizeof(f.body.init.data));
	r = sizeof(f.body.init.data);
	seq = 0;

	while ((size_t)r < flen) {
		if (rx_frame(d, &f, ms) < 0)
			LOG_RET(-1);

		LOG_BUF("continuation frame", (void *)&f, sizeof(f));
		if (f.cid != fido_dev_cid(d) || f.body.cont.seq != seq++)
			LOG_RET(-1);

		uint8_t *p = (uint8_t *)buf + r;

		if ((size_t)(flen - r) > sizeof(f.body.cont.data)) {
			memcpy(p, f.body.cont.data, sizeof(f.body.cont.data));
			r += sizeof(f.body.cont.data);
		} else {
			memcpy(p, f.body.cont.data, flen - r);
			r += (flen - r); /* break */
		}
	}

	LOG_BUF("payload", buf, r);

	LOG_RET(r);
}
