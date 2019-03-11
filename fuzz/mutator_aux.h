/*
 * Copyright (c) 2019 Yubico AB. All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file.
 */

#ifndef _MUTATOR_AUX_H
#define _MUTATOR_AUX_H

/*
 * As of LLVM 7.0.1, MSAN support in libFuzzer was still experimental.
 * We therefore have to be careful when using our custom mutator, or
 * MSAN will flag uninitialised reads on memory populated by libFuzzer.
 * Since there is no way to suppress MSAN without regenerating object
 * code (in which case you might as well rebuild libFuzzer with MSAN),
 * we adjust our mutator to make it less accurate while allowing
 * fuzzing to proceed.
 */

#if defined(__has_feature)
# if  __has_feature(memory_sanitizer)
#  define NO_MSAN	__attribute__((no_sanitize("memory")))
#  define WITH_MSAN	1
# endif
#endif

#if !defined(WITH_MSAN)
# define NO_MSAN
#endif

#define MAXSTR	1024
#define MAXBLOB	1024

struct blob {
	uint8_t body[MAXBLOB];
	size_t len;
};

int deserialize_blob(uint8_t, uint8_t **, size_t *, struct blob *);
int deserialize_bool(uint8_t, uint8_t **, size_t *, bool *);
int deserialize_int(uint8_t, uint8_t **, size_t *, int *);
int deserialize_string(uint8_t, uint8_t **, size_t *, char *);

int serialize_blob(uint8_t, uint8_t **, size_t *, const struct blob *);
int serialize_bool(uint8_t, uint8_t **, size_t *, bool);
int serialize_int(uint8_t, uint8_t **, size_t *, int);
int serialize_string(uint8_t, uint8_t **, size_t *, const char *);

#endif /* !_MUTATOR_AUX_H */
