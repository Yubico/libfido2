/*
 * Copyright (c) 2018 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#ifndef _FIDO_ES256_H
#define _FIDO_ES256_H

#include <openssl/ec.h>

#include <stdint.h>
#include <stdlib.h>

FIDO_PUBLIC_API es256_pk_t *es256_pk_new(void);
FIDO_PUBLIC_API void es256_pk_free(es256_pk_t **);
FIDO_PUBLIC_API EVP_PKEY *es256_pk_to_EVP_PKEY(const es256_pk_t *);

FIDO_PUBLIC_API int es256_pk_from_EC_KEY(es256_pk_t *, const EC_KEY *);
FIDO_PUBLIC_API int es256_pk_from_ptr(es256_pk_t *, const void *, size_t);

#ifdef _FIDO_INTERNAL
es256_sk_t *es256_sk_new(void);
void es256_sk_free(es256_sk_t **);
EVP_PKEY *es256_sk_to_EVP_PKEY(const es256_sk_t *);

int es256_derive_pk(const es256_sk_t *, es256_pk_t *);
int es256_sk_create(es256_sk_t *);

int es256_pk_set_x(es256_pk_t *, const unsigned char *);
int es256_pk_set_y(es256_pk_t *, const unsigned char *);
int es256_sk_set_d(es256_sk_t *, const unsigned char *);
#endif

#endif /* !_FIDO_ES256_H */
