/*
 * Copyright (c) 2019 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "mutator_aux.h"
#include "fido.h"
#include "fido/es256.h"

#include "../openbsd-compat/openbsd-compat.h"

#define TAG_TYPE	0x01
#define TAG_CDH		0x02	/* client data hash */
#define TAG_RP_ID	0x03
#define TAG_AUTHDATA	0x04
#define TAG_EXT		0x05
#define TAG_UP		0x06
#define TAG_UV		0x07
#define TAG_SIG		0x08
#define TAG_COUNT	0x09
#define TAG_PK		0x0a

struct param {
	bool		type;
	struct blob	cdh;
	char		rp_id[MAXSTR];
	struct blob	authdata;
	int		ext;
	bool		up;
	bool		uv;
	struct blob	sig;
	int		count;
	struct blob	pk;
};

static const uint8_t dummy_pk[64] = {
	0x34, 0xeb, 0x99, 0x77, 0x02, 0x9c, 0x36, 0x38,
	0xbb, 0xc2, 0xae, 0xa0, 0xa0, 0x18, 0xc6, 0x64,
	0xfc, 0xe8, 0x49, 0x92, 0xd7, 0x74, 0x9e, 0x0c,
	0x46, 0x8c, 0x9d, 0xa6, 0xdf, 0x46, 0xf7, 0x84,
	0x60, 0x1e, 0x0f, 0x8b, 0x23, 0x85, 0x4a, 0x9a,
	0xec, 0xc1, 0x08, 0x9f, 0x30, 0xd0, 0x0d, 0xd7,
	0x76, 0x7b, 0x55, 0x48, 0x91, 0x7c, 0x4f, 0x0f,
	0x64, 0x1a, 0x1d, 0xf8, 0xbe, 0x14, 0x90, 0x8a,
};

static const uint8_t dummy_cdh[32] = {
	0xec, 0x8d, 0x8f, 0x78, 0x42, 0x4a, 0x2b, 0xb7,
	0x82, 0x34, 0xaa, 0xca, 0x07, 0xa1, 0xf6, 0x56,
	0x42, 0x1c, 0xb6, 0xf6, 0xb3, 0x00, 0x86, 0x52,
	0x35, 0x2d, 0xa2, 0x62, 0x4a, 0xbe, 0x89, 0x76,
};

static const uint8_t dummy_authdata[39] = {
	0x58, 0x25, 0x49, 0x96, 0x0d, 0xe5, 0x88, 0x0e,
	0x8c, 0x68, 0x74, 0x34, 0x17, 0x0f, 0x64, 0x76,
	0x60, 0x5b, 0x8f, 0xe4, 0xae, 0xb9, 0xa2, 0x86,
	0x32, 0xc7, 0x99, 0x5c, 0xf3, 0xba, 0x83, 0x1d,
	0x97, 0x63, 0x00, 0x00, 0x00, 0x00, 0x03,
};

static const uint8_t dummy_sig[72] = {
	0x30, 0x46, 0x02, 0x21, 0x00, 0xf6, 0xd1, 0xa3,
	0xd5, 0x24, 0x2b, 0xde, 0xee, 0xa0, 0x90, 0x89,
	0xcd, 0xf8, 0x9e, 0xbd, 0x6b, 0x4d, 0x55, 0x79,
	0xe4, 0xc1, 0x42, 0x27, 0xb7, 0x9b, 0x9b, 0xa4,
	0x0a, 0xe2, 0x47, 0x64, 0x0e, 0x02, 0x21, 0x00,
	0xe5, 0xc9, 0xc2, 0x83, 0x47, 0x31, 0xc7, 0x26,
	0xe5, 0x25, 0xb2, 0xb4, 0x39, 0xa7, 0xfc, 0x3d,
	0x70, 0xbe, 0xe9, 0x81, 0x0d, 0x4a, 0x62, 0xa9,
	0xab, 0x4a, 0x91, 0xc0, 0x7d, 0x2d, 0x23, 0x1e,
};

static const char dummy_rp_id[] = "localhost";

int    LLVMFuzzerTestOneInput(const uint8_t *, size_t);
size_t LLVMFuzzerCustomMutator(uint8_t *, size_t, size_t, unsigned int);
size_t LLVMFuzzerMutate(uint8_t *, size_t, size_t);

static int
deserialize(const uint8_t *data, size_t size, struct param *p) NO_MSAN
{
	fido_assert_t *assert = NULL;

	if (deserialize_bool(TAG_TYPE, (void *)&data, &size, &p->type) < 0 ||
	    deserialize_blob(TAG_CDH, (void *)&data, &size, &p->cdh) < 0 ||
	    deserialize_string(TAG_RP_ID, (void *)&data, &size, p->rp_id) < 0 ||
	    deserialize_blob(TAG_AUTHDATA, (void *)&data, &size, &p->authdata) < 0 ||
	    deserialize_int(TAG_EXT, (void *)&data, &size, &p->ext) < 0 ||
	    deserialize_bool(TAG_UP, (void *)&data, &size, &p->up) < 0 ||
	    deserialize_bool(TAG_UV, (void *)&data, &size, &p->uv) < 0 ||
	    deserialize_blob(TAG_SIG, (void *)&data, &size, &p->sig) < 0 ||
	    deserialize_int(TAG_COUNT, (void *)&data, &size, &p->count) < 0 ||
	    deserialize_blob(TAG_PK, (void *)&data, &size, &p->pk) < 0)
		return (-1);

#ifndef WITH_MSAN
	if ((assert = fido_assert_new()) == NULL)
		return (-1);

	fido_assert_set_count(assert, 1);

	if (fido_assert_set_authdata(assert, 0, p->authdata.body,
	    p->authdata.len) != FIDO_OK) {
		fido_assert_free(&assert);
		return (-1);
	}
#endif

	fido_assert_free(&assert);

	return (0);
}

static size_t
serialize(uint8_t *ptr, size_t len, const struct param *p)
{
	const size_t max = len;

#ifndef WITH_MSAN
	fido_assert_t *assert = NULL;

	if ((assert = fido_assert_new()) == NULL)
		return (0);

	fido_assert_set_count(assert, 1);

	if (fido_assert_set_authdata(assert, 0, p->authdata.body,
	    p->authdata.len) != FIDO_OK) {
		fido_assert_free(&assert);
		return (0);
	}

	fido_assert_free(&assert);
#endif

	if (serialize_bool(TAG_TYPE, &ptr, &len, p->type) < 0 ||
	    serialize_blob(TAG_CDH, &ptr, &len, &p->cdh) < 0 ||
	    serialize_string(TAG_RP_ID, &ptr, &len, p->rp_id) < 0 ||
	    serialize_blob(TAG_AUTHDATA, &ptr, &len, &p->authdata) < 0 ||
	    serialize_int(TAG_EXT, &ptr, &len, p->ext) < 0 ||
	    serialize_bool(TAG_UP, &ptr, &len, p->up) < 0 ||
	    serialize_bool(TAG_UV, &ptr, &len, p->uv) < 0 ||
	    serialize_blob(TAG_SIG, &ptr, &len, &p->sig) < 0 ||
	    serialize_int(TAG_COUNT, &ptr, &len, p->count) < 0 ||
	    serialize_blob(TAG_PK, &ptr, &len, &p->pk) < 0)
		return (0);

	return (max - len);
}

static void
consume(const uint8_t *ptr, size_t len)
{
	volatile uint8_t x = 0;

	while (len--)
		x ^= *ptr++;
}
 
int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct param	 p;
	fido_assert_t	*assert = NULL;
	es256_pk_t	*pk = NULL;

	memset(&p, 0, sizeof(p));

	if (deserialize(data, size, &p) < 0)
		return (0);

	fido_init(0);

	if ((assert = fido_assert_new()) == NULL ||
	    (pk = es256_pk_new()) == NULL)
		return (0);

	es256_pk_from_ptr(pk, p.pk.body, p.pk.len);

	fido_assert_set_clientdata_hash(assert, p.cdh.body, p.cdh.len);
	fido_assert_set_rp(assert, p.rp_id);
	fido_assert_set_extensions(assert, p.ext);
	fido_assert_set_options(assert, p.up, p.uv);

	if (p.count > -1) {
		if (p.count > 1000)
			p.count = 1000;
		fido_assert_set_count(assert, (size_t)p.count);
	}

	fido_assert_set_authdata(assert, 0, p.authdata.body, p.authdata.len);
	fido_assert_set_sig(assert, 0, p.sig.body, p.sig.len);

	if (p.count > -1)
		for (size_t i = 0; i < (size_t)p.count; i++) {
			fido_assert_verify(assert, i, p.type, pk);
			consume(fido_assert_id_ptr(assert, i),
			    fido_assert_id_len(assert, i));
		}

	fido_assert_free(&assert);
	es256_pk_free(&pk);

	return (0);
}

size_t
LLVMFuzzerCustomMutator(uint8_t *data, size_t size, size_t maxsize,
    unsigned int seed)
{
	struct param	dummy;
	struct param	p;
	uint8_t		blob[4096];
	size_t		blob_len;
	size_t		n;

	(void)seed;

	memset(&p, 0, sizeof(p));

	if (deserialize(data, size, &p) < 0) {
		memset(&dummy, 0, sizeof(dummy));
		dummy.type = COSE_ES256;
		dummy.cdh.len = sizeof(dummy_cdh);
		memcpy(&dummy.cdh.body, &dummy_cdh, dummy.cdh.len);
		strlcpy(dummy.rp_id, dummy_rp_id, sizeof(dummy.rp_id));
		dummy.authdata.len = sizeof(dummy_authdata);
		memcpy(&dummy.authdata.body, &dummy_authdata, dummy.authdata.len);
		dummy.ext = FIDO_EXT_HMAC_SECRET;
		dummy.up = false;
		dummy.uv = false;
		dummy.pk.len = sizeof(dummy_pk);
		memcpy(&dummy.pk.body, &dummy_pk, dummy.pk.len);
		dummy.sig.len = sizeof(dummy_sig);
		memcpy(&dummy.sig.body, &dummy_sig, dummy.sig.len);
		dummy.count = 1;

		blob_len = serialize(blob, sizeof(blob), &dummy);
		assert(blob_len != 0);

		if (blob_len > maxsize) {
			memcpy(data, blob, maxsize);
			return (maxsize);
		}

		memcpy(data, blob, blob_len);
		return (blob_len);
	}

	LLVMFuzzerMutate((uint8_t *)&p.type, sizeof(p.type), sizeof(p.type));
	LLVMFuzzerMutate((uint8_t *)&p.ext, sizeof(p.ext), sizeof(p.ext));
	LLVMFuzzerMutate((uint8_t *)&p.up, sizeof(p.up), sizeof(p.up));
	LLVMFuzzerMutate((uint8_t *)&p.uv, sizeof(p.uv), sizeof(p.uv));
	LLVMFuzzerMutate((uint8_t *)&p.count, sizeof(p.count), sizeof(p.count));

	p.authdata.len = LLVMFuzzerMutate((uint8_t *)p.authdata.body,
	    p.authdata.len, sizeof(p.authdata.body));
	p.cdh.len = LLVMFuzzerMutate((uint8_t *)p.cdh.body, p.cdh.len,
	    sizeof(p.cdh.body));
	p.pk.len = LLVMFuzzerMutate((uint8_t *)p.pk.body, p.pk.len,
	    sizeof(p.pk.body));
	p.sig.len = LLVMFuzzerMutate((uint8_t *)p.sig.body, p.sig.len,
	    sizeof(p.sig.body));

	n = LLVMFuzzerMutate((uint8_t *)p.rp_id, strlen(p.rp_id), MAXSTR - 1);
	p.rp_id[n] = '\0';

	if ((blob_len = serialize(blob, sizeof(blob), &p)) == 0 ||
	    blob_len > maxsize)
		return (0);

	memcpy(data, blob, blob_len);

	return (blob_len);
}
