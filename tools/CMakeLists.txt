# Copyright (c) 2018 Yubico AB. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

list(APPEND COMPAT_SOURCES
	../openbsd-compat/explicit_bzero.c
	../openbsd-compat/strlcpy.c
	../openbsd-compat/strlcat.c
)

if(WIN32)
	list(APPEND COMPAT_SOURCES
		../openbsd-compat/bsd-getline.c
		../openbsd-compat/explicit_bzero_win32.c
		../openbsd-compat/getopt_long.c
		../openbsd-compat/posix_win.c
		../openbsd-compat/readpassphrase_win32.c
	)
else()
	list(APPEND COMPAT_SOURCES ../openbsd-compat/readpassphrase.c)
endif()

add_executable(fido2-cred
	fido2-cred.c
	cred_make.c
	cred_verify.c
	base64.c
	util.c
	${COMPAT_SOURCES}
)

add_executable(fido2-assert
	fido2-assert.c
	assert_get.c
	assert_verify.c
	base64.c
	util.c
	${COMPAT_SOURCES}
)

add_executable(fido2-token
	fido2-token.c
	base64.c
	bio.c
	credman.c
	pin.c
	token.c
	util.c
	${COMPAT_SOURCES}
)

add_library(sk-libfido2 MODULE sk-libfido2.c)
set_target_properties(sk-libfido2 PROPERTIES OUTPUT_NAME sk-libfido2)

target_link_libraries(fido2-cred ${CRYPTO_LIBRARIES} fido2_shared)
target_link_libraries(fido2-assert ${CRYPTO_LIBRARIES} fido2_shared)
target_link_libraries(fido2-token ${CRYPTO_LIBRARIES} fido2_shared)
target_link_libraries(sk-libfido2 ${CRYPTO_LIBRARIES} fido2_shared)

install(TARGETS fido2-cred fido2-assert fido2-token
	DESTINATION ${CMAKE_INSTALL_BINDIR})
install(TARGETS sk-libfido2 DESTINATION ${CMAKE_INSTALL_LIBDIR})
