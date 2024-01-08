/*
 * Copyright (c) 2018 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef _INT_ARRAY_H
#define _INT_ARRAY_H

#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct fido_int_array {
	int         *ptr;
    size_t       count;
} fido_int_array_t;


fido_int_array_t *fido_int_array_new(void);
int fido_int_array_is_empty(const fido_int_array_t *);
int fido_int_array_set(fido_int_array_t *, const int *, size_t);
int fido_int_array_append(fido_int_array_t *, const int *, size_t);
void fido_int_array_free(fido_int_array_t *);
void fido_int_array_reset(fido_int_array_t *);
void fido_free_int_array(fido_int_array_t *);
size_t fido_int_array_get_count(const fido_int_array_t *);
bool fido_int_array_contains(const fido_int_array_t* array, int element);

#ifdef __cplusplus
} /* extern "C" */
#endif /* __cplusplus */

#endif /* !_INT_ARRAY_H */
