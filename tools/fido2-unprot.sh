#!/bin/sh

# Copyright (c) 2020 Fabian Henneke.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

PREFIX=~/git/libfido2/build/tools/
TOKEN_OUTPUT=$(${PREFIX}fido2-token -L)
DEV_PATH_NAMES=$(echo "$TOKEN_OUTPUT" | sed -r 's/^(.*): .*\((.*)\)$/\1 \2/g')
DEV_COUNT=$(echo "$DEV_PATH_NAMES" | wc -l)

for i in $(seq 1 $DEV_COUNT)
do
    DEV_PATH_NAME=$(echo "$DEV_PATH_NAMES" | sed "${i}q;d")
    DEV_PATH=$(echo "$DEV_PATH_NAME" | cut -d' ' -f1)
    DEV_NAME=$(echo "$DEV_PATH_NAME" | cut -d' ' -f1 --complement)
    DEV_PRETTY=$(echo "$DEV_NAME (at '$DEV_PATH')")
    if expr match "$(${PREFIX}fido2-token -I $DEV_PATH)" ".* credMgmt.* clientPin.*\|.* clientPin.* credMgmt.*" > /dev/null ; then
        printf "Enter PIN for $DEV_PRETTY once (ignore further prompts): "
        stty -echo
        read PIN
        stty echo
        printf "\n"
        RESIDENT_RPS=$(echo "${PIN}\n" | setsid -w ${PREFIX}fido2-token -L -r $DEV_PATH | cut -d' ' -f3)
        printf "\n"
        RESIDENT_RPS_COUNT=$(echo "$RESIDENT_RPS" | wc -l)
        FOUND=0
        for j in $(seq 1 $DEV_RESIDENT_RPS_COUNT)
        do
            RESIDENT_RP=$(echo "$RESIDENT_RPS" | sed "${j}q;d")
            UNPROT_CREDS=$(echo "${PIN}\n" | setsid -w ${PREFIX}fido2-token -L -k $RESIDENT_RP $DEV_PATH | grep ' uvopt$' | cut -d' ' -f2,3,4)
            printf "\n"
            UNPROT_CREDS_COUNT=$(echo "$UNPROT_CREDS" | wc -l)
            if test $UNPROT_CREDS_COUNT -gt 0 ; then
                FOUND=1
                echo "Unprotected credentials on $DEV_PRETTY for '$RESIDENT_RP':"
                echo "$UNPROT_CREDS"
            fi
        done
        if test $FOUND -eq 0 ; then
            echo "No unprotected credentials on $DEV_PRETTY"
        fi
    else
        echo "$DEV_PRETTY cannot enumerate credentials"
        echo "Discovering unprotected SSH credentials only..."
        STUB_HASH=$(echo -n "" | sha256sum)
        ASSERT_OUTPUT=$(printf "$STUB_HASH\nssh:\n" | ${PREFIX}fido2-assert -G -r -t up=false $DEV_PATH 2> /dev/null)
        if test $? -eq 0 ; then
            echo "Found an unprotected SSH credential on $DEV_PRETTY!"
        else
            echo "No unprotected SSH credentials (default settings) on $DEV_PRETTY"
        fi
    fi
    printf "\n"
done
