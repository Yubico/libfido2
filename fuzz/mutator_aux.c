/*
 * Copyright (c) 2019 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mutator_aux.h"

int
deserialize_int(uint8_t t, uint8_t **ptr, size_t *len, int *v) NO_MSAN
{
	size_t l;

	if (*len < sizeof(t) || **ptr != t)
		return (-1);

	*ptr += sizeof(t);
	*len -= sizeof(t);

	if (*len < sizeof(l))
		return (-1);

	memcpy(&l, *ptr, sizeof(l));
	*ptr += sizeof(l);
	*len -= sizeof(l);

	if (l != sizeof(*v) || *len < l)
		return (-1);

	memcpy(v, *ptr, sizeof(*v));
	*ptr += sizeof(*v);
	*len -= sizeof(*v);

	return (0);
}

int
deserialize_string(uint8_t t, uint8_t **ptr, size_t *len, char *v) NO_MSAN
{
	size_t l;

	if (*len < sizeof(t) || **ptr != t)
		return (-1);

	*ptr += sizeof(t);
	*len -= sizeof(t);

	if (*len < sizeof(l))
		return (-1);

	memcpy(&l, *ptr, sizeof(l));
	*ptr += sizeof(l);
	*len -= sizeof(l);

	if (*len < l || l >= MAXSTR)
		return (-1);

	memcpy(v, *ptr, l);
	v[l] = '\0';

	*ptr += l;
	*len -= l;

	return (0);
}

int
deserialize_bool(uint8_t t, uint8_t **ptr, size_t *len, bool *v) NO_MSAN
{
	size_t l;

	if (*len < sizeof(t) || **ptr != t)
		return (-1);

	*ptr += sizeof(t);
	*len -= sizeof(t);

	if (*len < sizeof(l))
		return (-1);

	memcpy(&l, *ptr, sizeof(l));
	*ptr += sizeof(l);
	*len -= sizeof(l);

	if (l != sizeof(*v) || *len < l)
		return (-1);

	memcpy(v, *ptr, sizeof(*v));
	*ptr += sizeof(*v);
	*len -= sizeof(*v);

	return (0);
}

int
deserialize_blob(uint8_t t, uint8_t **ptr, size_t *len, struct blob *v) NO_MSAN
{
	size_t l;

	v->len = 0;

	if (*len < sizeof(t) || **ptr != t)
		return (-1);

	*ptr += sizeof(t);
	*len -= sizeof(t);

	if (*len < sizeof(l))
		return (-1);

	memcpy(&l, *ptr, sizeof(l));
	*ptr += sizeof(l);
	*len -= sizeof(l);

	if (*len < l || l > sizeof(v->body))
		return (-1);

	memcpy(v->body, *ptr, l);
	*ptr += l;
	*len -= l;

	v->len = l;

	return (0);
}

int
serialize_int(uint8_t t, uint8_t **ptr, size_t *len, int v) NO_MSAN
{
	const size_t l = sizeof(v);

	if (*len < sizeof(t) + sizeof(l) + l)
		return (-1);

	(*ptr)[0] = t;
	memcpy(&(*ptr)[sizeof(t)], &l, sizeof(l));
	memcpy(&(*ptr)[sizeof(t) + sizeof(l)], &v, l);

	*ptr += sizeof(t) + sizeof(l) + l;
	*len -= sizeof(t) + sizeof(l) + l;

	return (0);
}

int
serialize_string(uint8_t t, uint8_t **ptr, size_t *len, const char *v) NO_MSAN
{
	const size_t l = strlen(v);

	if (*len < sizeof(t) + sizeof(l) + l)
		return (-1);

	(*ptr)[0] = t;
	memcpy(&(*ptr)[sizeof(t)], &l, sizeof(l));
	memcpy(&(*ptr)[sizeof(t) + sizeof(l)], v, l);

	*ptr += sizeof(t) + sizeof(l) + l;
	*len -= sizeof(t) + sizeof(l) + l;

	return (0);
}

int
serialize_bool(uint8_t t, uint8_t **ptr, size_t *len, bool v) NO_MSAN
{
	const size_t l = sizeof(v);

	if (*len < sizeof(t) + sizeof(l) + l)
		return (-1);

	(*ptr)[0] = t;
	memcpy(&(*ptr)[sizeof(t)], &l, sizeof(l));
	memcpy(&(*ptr)[sizeof(t) + sizeof(l)], &v, l);

	*ptr += sizeof(t) + sizeof(l) + l;
	*len -= sizeof(t) + sizeof(l) + l;

	return (0);
}

int
serialize_blob(uint8_t t, uint8_t **ptr, size_t *len, const struct blob *v) NO_MSAN
{
	const size_t l = v->len;

	if (*len < sizeof(t) + sizeof(l) + l)
		return (-1);

	(*ptr)[0] = t;
	memcpy(&(*ptr)[sizeof(t)], &l, sizeof(l));
	memcpy(&(*ptr)[sizeof(t) + sizeof(l)], v->body, l);

	*ptr += sizeof(t) + sizeof(l) + l;
	*len -= sizeof(t) + sizeof(l) + l;

	return (0);
}
