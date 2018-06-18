# Copyright (c) 2018 Yubico AB. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

add_definitions(-D_FIDO_INTERNAL)

list(APPEND FIDO_SOURCES
	aes256.c
	assert.c
	authkey.c
	blob.c
	buf.c
	cbor.c
	cred.c
	dev.c
	ecdh.c
	err.c
	es256.c
	hid.c
	info.c
	io.c
	iso7816.c
	log.c
	pin.c
	reset.c
	rs256.c
	u2f.c
)

list(APPEND COMPAT_SOURCES
	../openbsd-compat/bsd-getpagesize.c
	../openbsd-compat/explicit_bzero.c
	../openbsd-compat/explicit_bzero_win32.c
	../openbsd-compat/recallocarray.c
	../openbsd-compat/timingsafe_bcmp.c
)

# /dev/urandom
if(UNIX)
	add_definitions(-DHAS_DEV_URANDOM)
endif()

add_library(fido2 STATIC ${FIDO_SOURCES} ${COMPAT_SOURCES})
target_link_libraries(fido2
	${CBOR_LIBRARIES}
	${CRYPTO_LIBRARIES}
	${HIDAPI_LIBRARIES})
if(WIN32)
	target_link_libraries(fido2 wsock32 ws2_32 bcrypt)
endif()

add_library(fido2_shared SHARED ${FIDO_SOURCES} ${COMPAT_SOURCES})
target_link_libraries(fido2_shared
	${CBOR_LIBRARIES}
	${CRYPTO_LIBRARIES}
	${HIDAPI_LIBRARIES})
if(WIN32)
	target_link_libraries(fido2_shared wsock32 ws2_32 bcrypt)
endif()

set_target_properties(fido2_shared PROPERTIES OUTPUT_NAME fido2
    VERSION ${FIDO_VERSION})

install(FILES fido.h DESTINATION include)
install(DIRECTORY fido DESTINATION include)
install(TARGETS fido2 fido2_shared ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})

configure_file(libfido2.pc.in libfido2.pc @ONLY)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/libfido2.pc"
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig")
