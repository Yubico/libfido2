# Copyright (c) 2018 Yubico AB. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

check_include_files(err.h HAVE_ERR_H)
if(HAVE_ERR_H)
	add_definitions(-DHAVE_ERR_H)
endif()

check_function_exists(strlcpy HAVE_STRLCPY)
if(HAVE_STRLCPY)
	add_definitions(-DHAVE_STRLCPY)
endif()

# manifest
add_executable(manifest manifest.c)
target_link_libraries(manifest fido2_shared)

# info
if(NOT HAVE_STRLCPY)
	add_executable(info info.c compat/strlcpy.c compat/strlcat.c)
else()
	add_executable(info info.c)
endif()
target_link_libraries(info fido2_shared)

# reset
add_executable(reset reset.c)
target_link_libraries(reset fido2_shared)

# cred
add_executable(cred cred.c util.c)
target_link_libraries(cred fido2_shared)

# assert
add_executable(assert assert.c util.c)
target_link_libraries(assert fido2_shared)

# setpin
add_executable(setpin setpin.c)
target_link_libraries(setpin fido2_shared)

# retries
add_executable(retries retries.c)
target_link_libraries(retries fido2_shared)
