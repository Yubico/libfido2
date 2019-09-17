# Copyright (c) 2018 Yubico AB. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

# cred
add_executable(regress_cred cred.c)
target_link_libraries(regress_cred fido2_shared)
add_custom_command(TARGET regress_cred POST_BUILD COMMAND regress_cred)

# assert
add_executable(regress_assert assert.c)
target_link_libraries(regress_assert fido2_shared)
add_custom_command(TARGET regress_assert POST_BUILD COMMAND regress_assert)

# dev
add_executable(regress_dev dev.c)
target_link_libraries(regress_dev fido2_shared)
add_custom_command(TARGET regress_dev POST_BUILD COMMAND regress_dev)
