/*
 * Copyright (c) 2018 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#ifndef _ES256_H
#define _ES256_H

/* ecdsa sha256 pubkey */
typedef struct es256_pk {
	unsigned char	x[32];
	unsigned char	y[32];
} es256_pk_t;

/* ecdsa sha256 private (secret) key */
typedef struct es256_sk {
	unsigned char	d[32];
} es256_sk_t;

cbor_item_t *	es256_pk_encode(const es256_pk_t *);
int		es256_pk_decode(const cbor_item_t *, es256_pk_t *);

#endif /* !_ES256_H */
