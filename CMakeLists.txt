# Copyright (c) 2018 Yubico AB. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

project(libfido2)
cmake_minimum_required(VERSION 3.0)

set(CMAKE_COLOR_MAKEFILE off)
set(CMAKE_VERBOSE_MAKEFILE on)
set(FIDO_MAJOR "0")
set(FIDO_MINOR "0")
set(FIDO_PATCH "0")
set(FIDO_VERSION ${FIDO_MAJOR}.${FIDO_MINOR}.${FIDO_PATCH})

include(FindPkgConfig)
pkg_search_module(CBOR libcbor REQUIRED)
if (APPLE)
	# Look for Homebrew's OpenSSL 1.1.
	set(OPENSSL_ROOT_DIR /usr/local/opt/openssl@1.1)
	find_package(openssl REQUIRED)
	set(CRYPTO_INCLUDE_DIRS ${OPENSSL_INCLUDE_DIR})
	set(CRYPTO_LIBRARY_DIRS ${OPENSSL_LIBRARY_DIR})
	set(CRYPTO_LIBRARIES ${OPENSSL_LIBRARIES})
	# Define memset_s().
	add_definitions(-D__STDC_WANT_LIB_EXT1__=1)
else()
	# Look for OpenSSL using pkg-config.
	pkg_search_module(CRYPTO libcrypto REQUIRED)
endif()
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
	# Use hidapi's raw API.
	pkg_search_module(HIDAPI hidapi-hidraw REQUIRED)
	# Define be32toh().
	add_definitions(-D_GNU_SOURCE)
else()
	pkg_search_module(HIDAPI hidapi REQUIRED)
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -W")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wextra")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wshadow")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wwrite-strings")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wmissing-prototypes")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wcast-qual")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wbad-function-cast")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pedantic")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pedantic-errors")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstack-protector-all")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99")
#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g")

# Use -Wshorten-64-to-32 if available.
include(CheckCCompilerFlag)
check_c_compiler_flag("-Wshorten-64-to-32" HAVE_SHORTEN_64_TO_32)
if (HAVE_SHORTEN_64_TO_32)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wshorten-64-to-32")
endif()

if(APPLE AND CMAKE_C_COMPILER_ID STREQUAL "Clang")
	string(CONCAT CMAKE_SHARED_LINKER_FLAGS ${CMAKE_SHARED_LINKER_FLAGS}
	    " -exported_symbols_list ${CMAKE_CURRENT_SOURCE_DIR}/src/export.llvm")
else()
	string(CONCAT CMAKE_SHARED_LINKER_FLAGS ${CMAKE_SHARED_LINKER_FLAGS}
	    " -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/src/export.gnu")
	if (NOT WIN32)
		string(CONCAT CMAKE_SHARED_LINKER_FLAGS
		    ${CMAKE_SHARED_LINKER_FLAGS}
		    " -Wl,-z,noexecstack -Wl,-z,relro,-z,now")
		string(CONCAT CMAKE_EXE_LINKER_FLAGS
		    ${CMAKE_EXE_LINKER_FLAGS}
		    " -Wl,-z,noexecstack -Wl,-z,relro,-z,now")
	endif()
endif()

include_directories(${CMAKE_SOURCE_DIR}/src)
include_directories(${CBOR_INCLUDE_DIRS})
include_directories(${CRYPTO_INCLUDE_DIRS})
include_directories(${HIDAPI_INCLUDE_DIRS})

link_directories(${CBOR_LIBRARY_DIRS})
link_directories(${CRYPTO_LIBRARY_DIRS})
link_directories(${HIDAPI_LIBRARY_DIRS})

#include(CPack)
#set(CPACK_GENERATOR "TGZ")
#set(CPACK_PACKAGE_VERSION_MAJOR ${FIDO_MAJOR})
#set(CPACK_PACKAGE_VERSION_MINOR ${FIDO_MINOR})
#set(CPACK_PACKAGE_VERSION_PATCH ${FIDO_PATCH})

message(STATUS "CMAKE_C_COMPILER: ${CMAKE_C_COMPILER}")
message(STATUS "CMAKE_C_COMPILER_ID: ${CMAKE_C_COMPILER_ID}")
message(STATUS "CBOR_INCLUDE_DIRS: ${CBOR_INCLUDE_DIRS}")
message(STATUS "CBOR_LIBRARY_DIRS: ${CBOR_LIBRARY_DIRS}")
message(STATUS "CBOR_LIBRARIES: ${CBOR_LIBRARIES}")
message(STATUS "CRYPTO_INCLUDE_DIRS: ${CRYPTO_INCLUDE_DIRS}")
message(STATUS "CRYPTO_LIBRARY_DIRS: ${CRYPTO_LIBRARY_DIRS}")
message(STATUS "CRYPTO_LIBRARIES: ${CRYPTO_LIBRARIES}")
message(STATUS "HIDAPI_INCLUDE_DIRS: ${HIDAPI_INCLUDE_DIRS}")
message(STATUS "HIDAPI_LIBRARY_DIRS: ${HIDAPI_LIBRARY_DIRS}")
message(STATUS "HIDAPI_LIBRARIES: ${HIDAPI_LIBRARIES}")

subdirs(src)
subdirs(examples)
