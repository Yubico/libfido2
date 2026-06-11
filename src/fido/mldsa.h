/*
 * Copyright (c) 2026 Yubico AB. All rights reserved.
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *    1. Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *    2. Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _FIDO_MLDSA_H
#define _FIDO_MLDSA_H

#include <openssl/evp.h>

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

mldsa44_pk_t *mldsa44_pk_new(void);
void mldsa44_pk_free(mldsa44_pk_t **);
EVP_PKEY *mldsa44_pk_to_EVP_PKEY(const mldsa44_pk_t *);
int mldsa44_pk_from_EVP_PKEY(mldsa44_pk_t *, const EVP_PKEY *);
int mldsa44_pk_from_ptr(mldsa44_pk_t *, const void *, size_t);

mldsa65_pk_t *mldsa65_pk_new(void);
void mldsa65_pk_free(mldsa65_pk_t **);
EVP_PKEY *mldsa65_pk_to_EVP_PKEY(const mldsa65_pk_t *);
int mldsa65_pk_from_EVP_PKEY(mldsa65_pk_t *, const EVP_PKEY *);
int mldsa65_pk_from_ptr(mldsa65_pk_t *, const void *, size_t);

mldsa87_pk_t *mldsa87_pk_new(void);
void mldsa87_pk_free(mldsa87_pk_t **);
EVP_PKEY *mldsa87_pk_to_EVP_PKEY(const mldsa87_pk_t *);
int mldsa87_pk_from_EVP_PKEY(mldsa87_pk_t *, const EVP_PKEY *);
int mldsa87_pk_from_ptr(mldsa87_pk_t *, const void *, size_t);

#ifdef __cplusplus
} /* extern "C" */
#endif /* __cplusplus */

#endif /* !_FIDO_MLDSA_H */
