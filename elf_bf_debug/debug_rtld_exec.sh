#!/bin/bash


# Copyright (c) 2012 Rebecca (bx) Shapiro

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# first argument is executable to run

ulimit -c unlimited

DIR=${PWD}/..
GLIBC=${PWD}/eglibc/eglibc-2.13
echo "set environment C -E -x c-header
python execfile(\"$PWD/elfbfgdb.py\")
break do-rel.h:116
break _dl_start
run --library-path $GLIBC:$GLIBC/nptl:$GLIBC/math:$GLIBC/elf:$GLIBC/dlfcn:$GLIBC/nss:$GLIBC/nis:$GLIBC/rt:$GLIBC/resolv:$GLIBC/crypt:$GLIBC/ntlp:$GLIBC/nplp_db $PWD/$1" > temp.gdb

${GLIBC}/../root/lib/ld-2.13.so   --library-path \
${GLIBC}:\
${GLIBC}/math:\
${GLIBC}/elf:\
${GLIBC}/dlfcn:\
${GLIBC}/nss:\
${GLIBC}/nis:\
${GLIBC}/rt:\
${GLIBC}/resolv:\
${GLIBC}/crypt:\
${GLIBC}/nptl:\
${GLIBC}/nptl_db:\
/lib/:\
/usr/lib/x86_64-linux-gnu/:\
/lib/x86_64-linux-gnu/:\
/usr/lib/: \
/usr/bin/ddd -x ${PWD}/temp.gdb -d ${GLIBC}  ${GLIBC}/../build/elf/ld.so