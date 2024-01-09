/*
 * Copyright (c) 2018-2022 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "fido.h"

void
fido_str_array_free(fido_str_array_t *sa)
{
	for (size_t i = 0; i < sa->len; i++)
		free(sa->ptr[i]);

	free(sa->ptr);
	sa->ptr = NULL;
	sa->len = 0;
}

void
fido_opt_array_free(fido_opt_array_t *oa)
{
	for (size_t i = 0; i < oa->len; i++)
		free(oa->name[i]);

	free(oa->name);
	free(oa->value);
	oa->name = NULL;
	oa->value = NULL;
	oa->len = 0;
}

void
fido_byte_array_free(fido_byte_array_t *ba)
{
	free(ba->ptr);

	ba->ptr = NULL;
	ba->len = 0;
}

void
fido_algo_free(fido_algo_t *a)
{
	free(a->type);
	a->type = NULL;
	a->cose = 0;
}

void
fido_algo_array_free(fido_algo_array_t *aa)
{
	for (size_t i = 0; i < aa->len; i++)
		fido_algo_free(&aa->ptr[i]);

	free(aa->ptr);
	aa->ptr = NULL;
	aa->len = 0;
}

void
fido_cert_array_free(fido_cert_array_t *ca)
{
	for (size_t i = 0; i < ca->len; i++)
		free(ca->name[i]);

	free(ca->name);
	free(ca->value);
	ca->name = NULL;
	ca->value = NULL;
	ca->len = 0;
}

int
fido_str_array_pack(fido_str_array_t *sa, const char * const *v, size_t n)
{
	if ((sa->ptr = calloc(n, sizeof(char *))) == NULL) {
		fido_log_debug("%s: calloc", __func__);
		return -1;
	}
	for (size_t i = 0; i < n; i++) {
		if ((sa->ptr[i] = strdup(v[i])) == NULL) {
			fido_log_debug("%s: strdup", __func__);
			return -1;
		}
		sa->len++;
	}

	return 0;
}

void
fido_int_array_reset(fido_int_array_t *array)
{
    freezero(array->ptr, array->count);
    explicit_bzero(array, sizeof(*array));
}

int
fido_int_array_set(fido_int_array_t *array, const int *ptr, size_t count)
{
    fido_int_array_reset(array);
    size_t len = count * sizeof(int);

    if (array == NULL || ptr == NULL || count == 0) {
        fido_log_debug("%s: array=%p, ptr=%p, count=%zu, len=%zu", __func__,
            (const void *)array, (const void *)ptr, count, len);
        return -1;
    }

    if ((array->ptr = malloc(len)) == NULL) {
        fido_log_debug("%s: malloc", __func__);
        return -1;
    }

    memcpy(array->ptr, ptr, len);
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

    if (SIZE_MAX - (array->count * sizeof(int)) < len) {
        fido_log_debug("%s: overflow", __func__);
        return -1;
    }
    if ((tmp = realloc(array->ptr, (array->count * sizeof(int)) + len)) == NULL) {
        fido_log_debug("%s: realloc", __func__);
        return -1;
    }
    array->ptr = tmp;
    memcpy(&array->ptr[(array->count * sizeof(int))], ptr, len);
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
    array->count = 0;
}

int
fido_int_array_is_empty(const fido_int_array_t *array)
{
    return array == NULL || array->ptr == NULL || array->count == 0;
}

size_t
fido_int_array_get_count(const fido_int_array_t *array)
{
    if (array == NULL || array->ptr == NULL)
        return 0;
    else
        return array->count;
}

bool
fido_int_array_contains(const fido_int_array_t* array, int element)
{
    if (array == NULL || array->ptr == NULL || array->count == 0)
        return false;

    for (size_t i = 0; i < array->count; i++) {
        if (element == array->ptr[i])
            return true;
    }

    return false;
}
