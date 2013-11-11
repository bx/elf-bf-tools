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

# compile_demo.sh is a wrapper script to compile the chosen
# brainfuck source into ../demo/demo's relocation entries,
# saving the version of demo with crafted relocaiton entries into
# ./demo

ENDOFFSET="-3f8"
TAPELEN="10"
SRC=""
while getopts ":hdl:i:" opt; do
  case $opt in
    d)
      ENDOFFSET="-428"
      ;;
    l)
      TAPELEN=$OPTARG
     ;;
    i)
      SRC=$OPTARG
    ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
      echo "usage: $0 -i <branfuck source> [optional: -l <tape length> -d]\n -d to compile binary to run in GDB" >&2
      ;;
    h)
      echo "usage: $0 -i <branfuck source> [optional: -l <tape length> -d]\n -d to compile binary to run in GDB" >&2
      ;;
  esac
done

if [ ! -f "$SRC" ]
then
    echo "source file $SRC does not exist\n" >&2
    exit 1
else
    echo "> $SRC" >&2
fi


# find dir script is located in
DIR="$( cd -P "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
#echo "$DIR/elf_bf_compiler ../demo/demo demo $SRC $TAPELEN demo.debug"
echo "$DIR/elf_bf_compiler ../demo/demo demo $SRC $ENDOFFSET demo.debug $TAPELEN"
$DIR/elf_bf_compiler ../demo/demo demo $SRC $ENDOFFSET demo.debug $TAPELEN

