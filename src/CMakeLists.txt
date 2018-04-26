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
	u2f.c
)

# endian.h
check_include_files(endian.h HAVE_ENDIAN_H)
if(HAVE_ENDIAN_H)
	add_definitions(-DHAVE_ENDIAN_H)
endif()

# recallocarray
check_function_exists(recallocarray HAVE_RECALLOCARRAY)
if(HAVE_RECALLOCARRAY)
	add_definitions(-DHAVE_RECALLOCARRAY)
else()
	list(APPEND FIDO_SOURCES compat/recallocarray.c)
endif()

# XXX: getpagesize is incorrectly detected when cross-compiling
# with mingw on Linux. Avoid.
if(NOT WIN32)
	check_function_exists(getpagesize HAVE_GETPAGESIZE)
endif()
if(HAVE_GETPAGESIZE)
	add_definitions(-DHAVE_GETPAGESIZE)
else()
	list(APPEND FIDO_SOURCES compat/bsd-getpagesize.c)
endif()

# sysconf
check_function_exists(sysconf HAVE_SYSCONF)
if(HAVE_SYSCONF)
	add_definitions(-DHAVE_SYSCONF)
endif()

# memset_s
check_function_exists(memset_s HAVE_MEMSET_S)
if(HAVE_MEMSET_S)
	add_definitions(-DHAVE_MEMSET_S)
endif()

# explicit_bzero
check_function_exists(explicit_bzero HAVE_EXPLICIT_BZERO)
if(HAVE_EXPLICIT_BZERO)
	add_definitions(-DHAVE_EXPLICIT_BZERO)
else()
	if(WIN32)
		list(APPEND FIDO_SOURCES compat/explicit_bzero_win32.c)
	else()
		list(APPEND FIDO_SOURCES compat/explicit_bzero.c)
	endif()
endif()

# /dev/urandom
if(UNIX)
	add_definitions(-DHAS_DEV_URANDOM)
endif()

add_library(fido2 STATIC ${FIDO_SOURCES})
target_link_libraries(fido2 ${CBOR_LIBRARIES} ${CRYPTO_LIBRARIES}
    ${HIDAPI_LIBRARIES})
if(WIN32)
	target_link_libraries(fido2 wsock32 ws2_32 bcrypt)
endif()

add_library(fido2_shared SHARED ${FIDO_SOURCES})
target_link_libraries(fido2_shared ${CBOR_LIBRARIES} ${CRYPTO_LIBRARIES}
    ${HIDAPI_LIBRARIES})
if(WIN32)
	target_link_libraries(fido2_shared wsock32 ws2_32 bcrypt)
endif()

set_target_properties(fido2_shared PROPERTIES OUTPUT_NAME fido2
    VERSION ${FIDO_VERSION})

install(FILES fido.h DESTINATION include)
install(DIRECTORY fido DESTINATION include REGEX "(compat).h" EXCLUDE)
install(TARGETS fido2 fido2_shared ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})

configure_file(libfido2.pc.in libfido2.pc @ONLY)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/libfido2.pc"
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig")
