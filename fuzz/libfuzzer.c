/*
 * Copyright (c) 2019 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mutator_aux.h"

static bool debug;
static unsigned long long test_fail;
static unsigned long long test_total;
static unsigned long long mutate_fail;
static unsigned long long mutate_total;

int LLVMFuzzerInitialize(int *, char ***);
int LLVMFuzzerTestOneInput(const uint8_t *, size_t);
size_t LLVMFuzzerCustomMutator(uint8_t *, size_t, size_t, unsigned int);

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
	for (int i = 0; i < *argc; i++)
		if (strcmp((*argv)[i], "--fido-debug") == 0)
			debug = 1;

	return 0;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct param *p;

	if (++test_total % 100000 == 0 && debug) {
		double r = (double)test_fail/(double)test_total * 100.0;
		fprintf(stderr, "%s: %llu/%llu (%.2f%%)\n", __func__,
		    test_fail, test_total, r);
	}

	if (size > 4096 || (p = unpack(data, size)) == NULL)
		test_fail++;
	else {
		test(p);
		free(p);
	}

	return 0;
}

size_t
LLVMFuzzerCustomMutator(uint8_t *data, size_t size, size_t maxsize,
    unsigned int seed) NO_MSAN
{
	struct param *p;
	uint8_t blob[4096];
	size_t blob_len;

	memset(&p, 0, sizeof(p));

#ifdef WITH_MSAN
	__msan_unpoison(data, maxsize);
#endif

	if (++mutate_total % 100000 == 0 && debug) {
		double r = (double)mutate_fail/(double)mutate_total * 100.0;
		fprintf(stderr, "%s: %llu/%llu (%.2f%%)\n", __func__,
		    mutate_fail, mutate_total, r);
	}

	if ((p = unpack(data, size)) == NULL) {
		mutate_fail++;
		return pack_dummy(data, maxsize);
	}

	mutate(p, seed);

	if ((blob_len = pack(blob, sizeof(blob), p)) == 0 ||
	    blob_len > sizeof(blob) || blob_len > maxsize) {
		mutate_fail++;
		free(p);
		return 0;
	}

	free(p);

	memcpy(data, blob, blob_len);

	return blob_len;
}
