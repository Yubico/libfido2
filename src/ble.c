/*
 * Copyright (c) 2023 Andreas Kemnade.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "fido.h"
#include "fido/param.h"

#define CTAPBLE_PING 0x81
#define CTAPBLE_KEEPALIVE 0x82
#define CTAPBLE_MSG 0x83
#define CTAPBLE_CANCEL 0xBE
#define CTAPBLE_ERROR 0xBF
#define CTAPBLE_MAX_FRAME_LEN 512
#define CTAPBLE_INIT_HEADER_LEN 3
#define CTAPBLE_CONT_HEADER_LEN 1


#ifndef MIN
#define MIN(x, y) ((x) > (y) ? (y) : (x))
#endif

union frame {
	struct {
		uint8_t cmd;
		uint8_t hlen;
		uint8_t llen;
		uint8_t data[CTAPBLE_MAX_FRAME_LEN - CTAPBLE_INIT_HEADER_LEN];
	} init;
	struct {
		uint8_t seq;
		uint8_t data[CTAPBLE_MAX_FRAME_LEN - CTAPBLE_CONT_HEADER_LEN];
	} cont;
};

static size_t
tx_preamble(fido_dev_t *d, uint8_t cmd, const u_char *buf, size_t count)
{
	union frame frag_buf;
	size_t fragment_len = MIN(fido_ble_get_cp_size(d), CTAPBLE_MAX_FRAME_LEN);
	int r;

	if (fragment_len <= CTAPBLE_INIT_HEADER_LEN)
		return 0;

	frag_buf.init.cmd = cmd;
	frag_buf.init.hlen = (count >> 8) & 0xff;
	frag_buf.init.llen = count & 0xff;

	count = MIN(count, fragment_len - CTAPBLE_INIT_HEADER_LEN);
	memcpy(frag_buf.init.data, buf, count);

	count += CTAPBLE_INIT_HEADER_LEN;
	r = d->io.write(d->io_handle, (const u_char *)&frag_buf, count);
	explicit_bzero(&frag_buf, sizeof(frag_buf));

	if ((r < 0) || ((size_t)r != count))
		return 0;

	return count - CTAPBLE_INIT_HEADER_LEN;
}

static size_t
tx_cont(fido_dev_t *d, uint8_t seq, const u_char *buf, size_t count)
{
	union frame frag_buf;
	int r;
	size_t fragment_len = MIN(fido_ble_get_cp_size(d), CTAPBLE_MAX_FRAME_LEN);

	if (fragment_len <= CTAPBLE_CONT_HEADER_LEN)
		return 0;

	frag_buf.cont.seq = seq;
	count = MIN(count, fragment_len - CTAPBLE_CONT_HEADER_LEN);
	memcpy(frag_buf.cont.data, buf, count);

	count += CTAPBLE_CONT_HEADER_LEN;
	r = d->io.write(d->io_handle, (const u_char *)&frag_buf, count);
	explicit_bzero(&frag_buf, sizeof(frag_buf));

	if ((r < 0) || ((size_t)r != count))
		return 0;

	return count - CTAPBLE_CONT_HEADER_LEN;
}

static int
fido_ble_fragment_tx(fido_dev_t *d, uint8_t cmd, const u_char *buf, size_t count)
{
	size_t n, sent;

	if ((sent = tx_preamble(d, cmd, buf, count)) == 0) {
		fido_log_debug("%s: tx_preamble", __func__);
		return (-1);
	}

	for (uint8_t seq = 0; sent < count; sent += n) {
		if ((n = tx_cont(d, seq++, buf + sent, count - sent)) == 0) {
			fido_log_debug("%s: tx_frame", __func__);
			return (-1);
		}

		seq &= 0x7f;
	}

	return 0;
}

int
fido_ble_tx(fido_dev_t *d, uint8_t cmd, const u_char *buf, size_t count)
{
	switch(cmd) {
	case CTAP_CMD_INIT:
		return 0;
	case CTAP_CMD_CBOR:
	case CTAP_CMD_MSG:
		return fido_ble_fragment_tx(d, CTAPBLE_MSG, buf, count);
	default:
		fido_log_debug("%s: unsupported command %02x", __func__, cmd);
		return -1;
	}
}

static int
rx_init(fido_dev_t *d, unsigned char *buf, size_t count, int ms)
{
	(void)ms;
	fido_ctap_info_t *attr = (fido_ctap_info_t *)buf;
	if (count != sizeof(*attr)) {
		fido_log_debug("%s: count=%zu", __func__, count);
		return -1;
	}

	memset(attr, 0, sizeof(*attr));

	/* we allow only FIDO2 devices for now for simplicity */
	attr->flags = FIDO_CAP_CBOR | FIDO_CAP_NMSG;
	memcpy(&attr->nonce, &d->nonce, sizeof(attr->nonce));

	return (int)count;
}

static int
rx_preamble(fido_dev_t *d, unsigned char **buf, size_t *count, size_t *reply_length, int ms)
{
	union frame reply;
	int ret;
	size_t payload;
	size_t fragment_len = fido_ble_get_cp_size(d);

	if (fragment_len <= CTAPBLE_INIT_HEADER_LEN) {
		return -1;
	}

	payload = fragment_len - CTAPBLE_INIT_HEADER_LEN;
	if (*count < payload)
		payload = *count;

	do {
		ret = d->io.read(d->io_handle, (u_char *)&reply,
		    payload + CTAPBLE_INIT_HEADER_LEN, ms);
		if (ret <= 0) {
			fido_log_debug("%s: read header", __func__);
			goto out;
		}
	} while (reply.init.cmd == CTAPBLE_KEEPALIVE);

	if ((reply.init.cmd != CTAPBLE_MSG) || ret <= CTAPBLE_INIT_HEADER_LEN) {
		ret = -1;
		goto out;
	}
	ret -= CTAPBLE_INIT_HEADER_LEN;
	*reply_length = ((size_t)reply.init.hlen) << 8 | reply.init.llen;
	if (*reply_length > *count) {
		fido_log_debug("%s: more data in reply than expected", __func__);
		ret = -1;
		goto out;
	}

	*count = MIN(*reply_length, *count);

	if (fido_buf_write(buf, count, reply.init.data, (size_t)ret) < 0) {
		ret = -1;
		goto out;
	}
	ret = 0;
out:
	explicit_bzero(&reply, sizeof(reply));
	return ret;
}

static int
rx_cont(fido_dev_t *d, unsigned char **buf, uint8_t seq, size_t *count, int ms)
{
	union frame reply;
	int ret;
	size_t payload;
	size_t fragment_len = fido_ble_get_cp_size(d);
	payload = fragment_len - CTAPBLE_CONT_HEADER_LEN;
	payload = MIN(*count, payload);
	ret = d->io.read(d->io_handle, (u_char *) &reply,
	    payload + CTAPBLE_CONT_HEADER_LEN, ms);

	if (ret <= CTAPBLE_CONT_HEADER_LEN) {
		if (ret >= 0)
			ret = -1;
		fido_log_debug("%s: read cont", __func__);
		goto out;
	}
	ret -= CTAPBLE_CONT_HEADER_LEN;
	if (reply.cont.seq != seq) {
		ret = -1;
		goto out;
	}

	if (fido_buf_write(buf, count, reply.cont.data, (size_t)ret) < 0)
		ret = -1;

out:
	explicit_bzero(&reply, sizeof(reply));
	return ret;
}

static int
rx_fragments(fido_dev_t *d, unsigned char *buf, size_t count, int ms)
{
	uint8_t seq;
	size_t reply_length;

	/* written on success in rx_preamble but clang does not know */
	reply_length = 0;
	if (rx_preamble(d, &buf, &count, &reply_length, ms) < 0)
		return -1;

	seq = 0;
	while(count > 0) {
		if (rx_cont(d, &buf, seq, &count, ms) < 0)
			return -1;

		seq++;
		seq &= 0x7f;
	}
	return (int)reply_length;
}

int
fido_ble_rx(fido_dev_t *d, uint8_t cmd, u_char *buf, size_t count, int ms)
{
	switch(cmd) {
	case CTAP_CMD_INIT:
		return rx_init(d, buf, count, ms);
	case CTAP_CMD_CBOR:
		return rx_fragments(d, buf, count, ms);
	default:
		fido_log_debug("%s: unsupported command %02x", __func__, cmd);
		return -1;
	}
}

bool
fido_is_ble(const char *path)
{
	return !strncmp(path, FIDO_BLE_PREFIX, strlen(FIDO_BLE_PREFIX));
}

int
fido_dev_set_ble(fido_dev_t *d)
{
	if (d->io_handle != NULL) {
		fido_log_debug("%s: device open", __func__);
		return -1;
	}
	d->io_own = true;
	d->io = (fido_dev_io_t) {
		fido_ble_open,
		fido_ble_close,
		fido_ble_read,
		fido_ble_write,
	};
	d->transport = (fido_dev_transport_t) {
		fido_ble_rx,
		fido_ble_tx,
	};

	return 0;
}

