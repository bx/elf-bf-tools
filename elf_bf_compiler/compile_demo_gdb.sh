#!/bin/bash
#   Copyright (c) 2012 Rebecca (bx) Shapiro

#   Permission is hereby granted, free of charge, to any person obtaining a copy
#   of this software and associated documentation files (the "Software"), to deal
#   in the Software without restriction, including without limitation the rights
#   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#   copies of the Software, and to permit persons to whom the Software is
#   furnished to do so, subject to the following conditions:

#   The above copyright notice and this permission notice shall be included in all
#   copies or substantial portions of the Software.

#   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#   SOFTWARE.

# compile_demo_gdb.sh does everything compile_demo.sh does
# while also runing elf_bf_compiler inside gdb to debug
# compilation

if [ $1 ]; then
    SRC=$1
else
    echo "usage: $0 <branfuck source> [optional: tape length]"
fi

if [ $2 ]; then
    TAPELEN=$2
else
    TAPELEN=10
fi
# lookup directory script lives in
DIR="$( cd -P "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
gdb --args  elf_bf_compiler ../demo/demo demo $SRC $TAPELEN demo.debug
