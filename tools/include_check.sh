#!/bin/sh

# Copyright (c) 2019 Yubico AB. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.
# SPDX-License-Identifier: BSD-2-Clause

rc=0
try="cc $CFLAGS -Isrc -xc -c - -o /dev/null 2>&1"
for header in "$@"; do
	body="#include \"$header\""
	echo "echo $body | $try"
	echo "$body" | eval "$try" || rc=1
done
exit "$rc"
