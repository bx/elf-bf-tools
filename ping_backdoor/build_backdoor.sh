#!/bin/sh

INPUT=inetutils/inetutils-1.8/ping/ping
OUTPUT=ping
LIBC=`ldd $INPUT | grep libc.so.6 | awk '{print $3}'`
echo "running ./ping_backdoor $INPUT $OUTPUT $LIBC"
./ping_backdoor $INPUT $OUTPUT $LIBC