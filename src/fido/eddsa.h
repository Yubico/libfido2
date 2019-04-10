/*
 * Copyright (c) 2019 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#ifndef _FIDO_EDDSA_H
#define _FIDO_EDDSA_H

#include <openssl/ec.h>

#include <stdint.h>
#include <stdlib.h>

eddsa_pk_t *eddsa_pk_new(void);
void eddsa_pk_free(eddsa_pk_t **);
EVP_PKEY *eddsa_pk_to_EVP_PKEY(const eddsa_pk_t *);

int eddsa_pk_from_EVP_PKEY(eddsa_pk_t *, const EVP_PKEY *);
int eddsa_pk_from_ptr(eddsa_pk_t *, const void *, size_t);

#ifdef _FIDO_INTERNAL
int eddsa_pk_set_x(eddsa_pk_t *, const unsigned char *);
#endif

#endif /* !_FIDO_EDDSA_H */
