# Copyright (c) 2019 Yubico AB. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

list(APPEND COMPAT_SOURCES
	../openbsd-compat/strlcpy.c
)

if(LIBFUZZER)
	# fuzz_cred
	add_executable(fuzz_cred fuzz_cred.c mutator_aux.c ${COMPAT_SOURCES})
	target_compile_options(fuzz_cred PRIVATE "-fsanitize=fuzzer")
	target_link_options(fuzz_cred PRIVATE "-fsanitize=fuzzer")
	target_link_libraries(fuzz_cred fido2_shared)
endif()
