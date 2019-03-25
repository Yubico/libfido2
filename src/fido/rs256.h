/*
 * Copyright (c) 2018 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#ifndef _FIDO_RS256_H
#define _FIDO_RS256_H

#include <openssl/rsa.h>

#include <stdint.h>
#include <stdlib.h>

FIDO_PUBLIC_API rs256_pk_t *rs256_pk_new(void);
FIDO_PUBLIC_API void rs256_pk_free(rs256_pk_t **);
FIDO_PUBLIC_API EVP_PKEY *rs256_pk_to_EVP_PKEY(const rs256_pk_t *);

FIDO_PUBLIC_API int rs256_pk_from_RSA(rs256_pk_t *, const RSA *);
FIDO_PUBLIC_API int rs256_pk_from_ptr(rs256_pk_t *, const void *, size_t);

#endif /* !_FIDO_RS256_H */
