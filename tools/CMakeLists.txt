# Copyright (c) 2018 Yubico AB. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

add_executable(fido2-cred
	fido2-cred.c
	cred_make.c
	cred_verify.c
	base64.c
	util.c
	../openbsd-compat/explicit_bzero.c
	../openbsd-compat/readpassphrase.c
)

add_executable(fido2-credman
	fido2-credman.c
	base64.c
	credman.c
	pin.c
	util.c
	../openbsd-compat/strlcpy.c
	../openbsd-compat/strlcat.c
	../openbsd-compat/explicit_bzero.c
	../openbsd-compat/readpassphrase.c
)

add_executable(fido2-assert
	fido2-assert.c
	assert_get.c
	assert_verify.c
	base64.c
	util.c
	../openbsd-compat/explicit_bzero.c
	../openbsd-compat/readpassphrase.c
)

add_executable(fido2-token
	fido2-token.c
	base64.c
	pin.c
	token.c
	util.c
	../openbsd-compat/strlcpy.c
	../openbsd-compat/strlcat.c
	../openbsd-compat/explicit_bzero.c
	../openbsd-compat/readpassphrase.c
)

target_link_libraries(fido2-cred ${CRYPTO_LIBRARIES} fido2_shared)
target_link_libraries(fido2-credman ${CRYPTO_LIBRARIES} fido2_shared)
target_link_libraries(fido2-assert ${CRYPTO_LIBRARIES} fido2_shared)
target_link_libraries(fido2-token ${CRYPTO_LIBRARIES} fido2_shared)

install(TARGETS fido2-cred fido2-credman fido2-assert fido2-token
	DESTINATION ${CMAKE_INSTALL_BINDIR})
