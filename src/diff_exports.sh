#!/bin/bash -u

# Copyright (c) 2018 Yubico AB. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

[[ ! -f export.gnu || ! -f export.llvm ]] && exit 1

TMPDIR=$(mktemp -d)
GNU=${TMPDIR}/gnu
LLVM=${TMPDIR}/llvm

egrep -o $'([^*{}\t]+);$' export.gnu | tr -d ';' | sort > ${GNU}
sed 's/^_//g' export.llvm | sort > ${LLVM}
diff -u ${GNU} ${LLVM}
ERROR=$?

rm ${GNU} ${LLVM}
rmdir ${TMPDIR}

exit ${ERROR}
