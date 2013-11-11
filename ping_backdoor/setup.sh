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


# this is only guaranteed to work in ubuntu 11.10
mkdir inetutils
cd inetutils
sudo apt-get build-dep inetutils
apt-get source inetutils
cd inetutils-1.8
GLIBC=$PWD/../../../elf_bf_debug/eglibc/root
LD=$GLIBC/lib/ld-linux-x86-64.so.2
if [ -f $LD ] ; then
    CFLAGS="-g -Wl,-dynamic-linker=$LD -Wl,-R$GLIBC/lib/ -I$GLIBC/include -L$GLIBC/lib" ./configure --disable-servers
else
    echo "WARNING: eglibc not built yet, ping_backdoor will not work properly. Look at ../elf_bf_debug/README for information on how to eglibc"
    ./configure
fi

make -j 8
