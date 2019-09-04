# Copyright (c) 2019 Yubico AB. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

list(APPEND COMPAT_SOURCES
	../openbsd-compat/strlcpy.c
	../openbsd-compat/strlcat.c
)

if(LIBFUZZER)
	# fuzz_cred
	add_executable(fuzz_cred fuzz_cred.c mutator_aux.c ${COMPAT_SOURCES})
	target_compile_options(fuzz_cred PRIVATE "-fsanitize=fuzzer")
	set_target_properties(fuzz_cred PROPERTIES LINK_FLAGS "-fsanitize=fuzzer")
	target_link_libraries(fuzz_cred fido2_shared)

	# fuzz_assert
	add_executable(fuzz_assert fuzz_assert.c mutator_aux.c ${COMPAT_SOURCES})
	target_compile_options(fuzz_assert PRIVATE "-fsanitize=fuzzer")
	set_target_properties(fuzz_assert PROPERTIES LINK_FLAGS "-fsanitize=fuzzer")
	target_link_libraries(fuzz_assert fido2_shared)

	# fuzz_mgmt
	add_executable(fuzz_mgmt fuzz_mgmt.c mutator_aux.c ${COMPAT_SOURCES})
	target_compile_options(fuzz_mgmt PRIVATE "-fsanitize=fuzzer")
	set_target_properties(fuzz_mgmt PROPERTIES LINK_FLAGS "-fsanitize=fuzzer")
	target_link_libraries(fuzz_mgmt fido2_shared)

	# fuzz_credman
	add_executable(fuzz_credman fuzz_credman.c mutator_aux.c ${COMPAT_SOURCES})
	target_compile_options(fuzz_credman PRIVATE "-fsanitize=fuzzer")
	set_target_properties(fuzz_credman PROPERTIES LINK_FLAGS "-fsanitize=fuzzer")
	target_link_libraries(fuzz_credman fido2_shared)

	# fuzz_bio
	add_executable(fuzz_bio fuzz_bio.c mutator_aux.c ${COMPAT_SOURCES})
	target_compile_options(fuzz_bio PRIVATE "-fsanitize=fuzzer")
	set_target_properties(fuzz_bio PROPERTIES LINK_FLAGS "-fsanitize=fuzzer")
	target_link_libraries(fuzz_bio fido2_shared)
endif()
