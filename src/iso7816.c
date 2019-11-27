/*
 * Copyright (c) 2018 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <string.h>
#include "fido.h"

struct iso7816_apdu {
	size_t max_len;
	size_t len;
	uint8_t buf[];
};

iso7816_apdu_t *
iso7816_new(uint8_t ins, uint8_t p1, uint16_t payload_len)
{
	iso7816_apdu_t	*apdu;
	size_t		 max_len;
	enum {
		CLA,
		INS,
		P1,
		P2,
		LC1,
		LC2,
		LC3,
		DATA,
	};

	max_len = DATA + payload_len;

	if ((apdu = calloc(1, sizeof(*apdu) + max_len)) == NULL)
		return (NULL);

	apdu->max_len = max_len;
	apdu->buf[INS] = ins;
	apdu->buf[P1] = p1;
	apdu->buf[LC2] = (payload_len >> 8) & 0xff;
	apdu->buf[LC3] = payload_len & 0xff;
	apdu->len = DATA;

	return (apdu);
}

void
iso7816_free(iso7816_apdu_t **apdu_p)
{
	iso7816_apdu_t *apdu;

	if (apdu_p == NULL || (apdu = *apdu_p) == NULL)
		return;

	explicit_bzero(apdu, sizeof(*apdu) + apdu->max_len);
	free(apdu);

	*apdu_p = NULL;
}

int
iso7816_add(iso7816_apdu_t *apdu, const void *buf, size_t cnt)
{
	if (cnt > apdu->max_len - apdu->len)
		return (-1);

	memcpy(apdu->buf + apdu->len, buf, cnt);
	apdu->len += cnt;

	return (0);
}

const unsigned char *
iso7816_ptr(const iso7816_apdu_t *apdu)
{
	return ((const unsigned char *)&apdu->buf);
}

size_t
iso7816_len(const iso7816_apdu_t *apdu)
{
	return (apdu->len);
}
