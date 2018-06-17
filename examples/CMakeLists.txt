# Copyright (c) 2018 Yubico AB. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

list(APPEND COMPAT_SOURCES
	../openbsd-compat/strlcpy.c
	../openbsd-compat/strlcat.c
)

# manifest
add_executable(manifest manifest.c)
target_link_libraries(manifest fido2_shared)

# info
add_executable(info info.c ${COMPAT_SOURCES})
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
