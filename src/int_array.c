/*
 * Copyright (c) 2018 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "fido.h"

fido_int_array_t *
fido_int_array_new(void)
{
	return calloc(1, sizeof(fido_int_array_t));
}

void
fido_int_array_reset(fido_int_array_t *array)
{
	freezero(array->ptr, array->len);
	explicit_bzero(array, sizeof(*array));
}

int
fido_int_array_set(fido_int_array_t *array, const int *ptr, size_t count)
{
    fido_int_array_reset(array);
    size_t len = count * sizeof(int);

    if (array == NULL || ptr == NULL || count == 0) {
		fido_log_debug("%s: array=%p, ptr=%p, count=%zu, len=%zu", __func__,
		    (const void *) array, (const void *)ptr, count, len);
		return -1;
	}

	if ((array->ptr = malloc(len)) == NULL) {
		fido_log_debug("%s: malloc", __func__);
		return -1;
	}

	memcpy(array->ptr, ptr, len);
	array->len = len;
    array->count = count;

	return 0;
}

int
fido_int_array_append(fido_int_array_t *array, const int *ptr, size_t count)
{
	int *tmp;
    size_t len = count * sizeof(int);

    if (array == NULL || ptr == NULL || count == 0) {
        fido_log_debug("%s: array=%p, ptr=%p, count=%zu, len=%zu", __func__,
            (const void *)array, (const void *)ptr, count, len);
        return -1;
    }

	if (SIZE_MAX - array->len < len) {
		fido_log_debug("%s: overflow", __func__);
		return -1;
	}
	if ((tmp = realloc(array->ptr, array->len + len)) == NULL) {
		fido_log_debug("%s: realloc", __func__);
		return -1;
	}
	array->ptr = tmp;
	memcpy(&array->ptr[array->len], ptr, len);
	array->len += len;
    array->count += count;

	return 0;
}

void
fido_int_array_free(fido_int_array_t *array)
{
    if (array == NULL || array->ptr == NULL)
        return;

    free(array->ptr);
    array->ptr = NULL;
    array->len = 0;
    array->count = 0;
}

int
fido_int_array_is_empty(const fido_int_array_t *array)
{
	return array == NULL || array->ptr == NULL || array->len == 0;
}

size_t
fido_int_array_get_count(const fido_int_array_t *array)
{
    if (array == NULL || array->ptr == NULL)
        return 0;
    else
        return array->count;
}