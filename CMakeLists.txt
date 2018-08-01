# Copyright (c) 2018 Yubico AB. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

project(libfido2)
cmake_minimum_required(VERSION 3.0)

include(CheckCCompilerFlag)
include(CheckFunctionExists)
include(CheckFunctionExists)
include(CheckIncludeFiles)
include(CheckIncludeFiles)
include(FindPkgConfig)
include(GNUInstallDirs)

set(CMAKE_COLOR_MAKEFILE off)
set(CMAKE_VERBOSE_MAKEFILE on)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(FIDO_MAJOR "0")
set(FIDO_MINOR "3")
set(FIDO_PATCH "0")
set(FIDO_VERSION ${FIDO_MAJOR}.${FIDO_MINOR}.${FIDO_PATCH})

add_definitions(-D_FIDO_MAJOR=${FIDO_MAJOR})
add_definitions(-D_FIDO_MINOR=${FIDO_MINOR})
add_definitions(-D_FIDO_PATCH=${FIDO_PATCH})

pkg_search_module(CBOR libcbor)
pkg_search_module(CRYPTO libcrypto REQUIRED)

if(NOT CBOR_FOUND)
	set(CBOR_LIBRARIES "cbor")
endif()

if(APPLE)
	# Define memset_s().
	add_definitions(-D__STDC_WANT_LIB_EXT1__=1)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
	# Use hidapi's raw API.
	pkg_search_module(HIDAPI hidapi-hidraw REQUIRED)
	set(HIDAPI_NAME "hidapi-hidraw")
	# Define be32toh().
	add_definitions(-D_GNU_SOURCE)
else()
	pkg_search_module(HIDAPI hidapi REQUIRED)
	set(HIDAPI_NAME "hidapi")
endif()

# MinGW is stuck with a flavour of C89.
if(MINGW)
	add_definitions(-DFIDO_NO_DIAGNOSTIC)
endif()

# fuzz instrumentation
if(FUZZ)
	add_definitions(-DFIDO_FUZZ)
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
if(FUZZ)
	# -fsanitize-trap=undefined is a superset of -ftrapv
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize-trap=undefined")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g")
endif()
#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ftrapv")
#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g")

# Use -Wshorten-64-to-32 if available.
check_c_compiler_flag("-Wshorten-64-to-32" HAVE_SHORTEN_64_TO_32)
if(HAVE_SHORTEN_64_TO_32)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wshorten-64-to-32")
endif()

# Avoid https://gcc.gnu.org/bugzilla/show_bug.cgi?id=66425
if(CMAKE_COMPILER_IS_GNUCC)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-unused-result")
endif()

# endian.h
check_include_files(endian.h HAVE_ENDIAN_H)
if(HAVE_ENDIAN_H)
	add_definitions(-DHAVE_ENDIAN_H)
endif()

# err.h
check_include_files(err.h HAVE_ERR_H)
if(HAVE_ERR_H)
	add_definitions(-DHAVE_ERR_H)
endif()

# strlcpy
check_function_exists(strlcpy HAVE_STRLCPY)
if(HAVE_STRLCPY)
	add_definitions(-DHAVE_STRLCPY)
endif()

# strlcat
check_function_exists(strlcpy HAVE_STRLCAT)
if(HAVE_STRLCAT)
	add_definitions(-DHAVE_STRLCAT)
endif()

# recallocarray
check_function_exists(recallocarray HAVE_RECALLOCARRAY)
if(HAVE_RECALLOCARRAY)
	add_definitions(-DHAVE_RECALLOCARRAY)
endif()

# XXX getpagesize is incorrectly detected when cross-compiling
# with mingw on Linux. Avoid.
if(NOT WIN32)
	check_function_exists(getpagesize HAVE_GETPAGESIZE)
endif()
if(HAVE_GETPAGESIZE)
	add_definitions(-DHAVE_GETPAGESIZE)
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
endif()

# timingsafe_bcmp
check_function_exists(timingsafe_bcmp HAVE_TIMINGSAFE_BCMP)
if(HAVE_TIMINGSAFE_BCMP)
	add_definitions(-DHAVE_TIMINGSAFE_BCMP)
endif()

# readpassphrase
check_function_exists(readpassphrase HAVE_READPASSPHRASE)
if(HAVE_READPASSPHRASE)
	add_definitions(-DHAVE_READPASSPHRASE)
endif()

# export list
if(APPLE AND CMAKE_C_COMPILER_ID STREQUAL "Clang")
	string(CONCAT CMAKE_SHARED_LINKER_FLAGS ${CMAKE_SHARED_LINKER_FLAGS}
	    " -exported_symbols_list ${CMAKE_CURRENT_SOURCE_DIR}/src/export.llvm")
else()
	string(CONCAT CMAKE_SHARED_LINKER_FLAGS ${CMAKE_SHARED_LINKER_FLAGS}
	    " -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/src/export.gnu")
	if(NOT WIN32)
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

message(STATUS "CMAKE_C_COMPILER: ${CMAKE_C_COMPILER}")
message(STATUS "CMAKE_C_COMPILER_ID: ${CMAKE_C_COMPILER_ID}")
message(STATUS "CMAKE_INSTALL_PREFIX: ${CMAKE_INSTALL_PREFIX}")
message(STATUS "CMAKE_INSTALL_LIBDIR: ${CMAKE_INSTALL_LIBDIR}")
message(STATUS "CBOR_INCLUDE_DIRS: ${CBOR_INCLUDE_DIRS}")
message(STATUS "CBOR_LIBRARY_DIRS: ${CBOR_LIBRARY_DIRS}")
message(STATUS "CBOR_LIBRARIES: ${CBOR_LIBRARIES}")
message(STATUS "CRYPTO_INCLUDE_DIRS: ${CRYPTO_INCLUDE_DIRS}")
message(STATUS "CRYPTO_LIBRARY_DIRS: ${CRYPTO_LIBRARY_DIRS}")
message(STATUS "CRYPTO_LIBRARIES: ${CRYPTO_LIBRARIES}")
message(STATUS "HIDAPI_INCLUDE_DIRS: ${HIDAPI_INCLUDE_DIRS}")
message(STATUS "HIDAPI_LIBRARY_DIRS: ${HIDAPI_LIBRARY_DIRS}")
message(STATUS "HIDAPI_LIBRARIES: ${HIDAPI_LIBRARIES}")
message(STATUS "VERSION: ${FIDO_MAJOR}.${FIDO_MINOR}.${FIDO_PATCH}")
message(STATUS "FUZZ: ${FUZZ}")

subdirs(src)
subdirs(examples)
if(NOT WIN32)
subdirs(regress)
subdirs(tools)
endif()
subdirs(man)
