/*
 * Copyright (c) 2022 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#ifndef _FIDO_ES384_H
#define _FIDO_ES384_H

#include <openssl/ec.h>

#include <stdint.h>
#include <stdlib.h>

#ifdef _FIDO_INTERNAL
#include "types.h"
#else
#include <fido.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

es384_pk_t *es384_pk_new(void);
void es384_pk_free(es384_pk_t **);
EVP_PKEY *es384_pk_to_EVP_PKEY(const es384_pk_t *);

int es384_pk_from_EC_KEY(es384_pk_t *, const EC_KEY *);
int es384_pk_from_ptr(es384_pk_t *, const void *, size_t);

#ifdef __cplusplus
} /* extern "C" */
#endif /* __cplusplus */

#endif /* !_FIDO_ES384_H */
