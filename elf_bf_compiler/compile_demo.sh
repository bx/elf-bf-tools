#!/bin/bash

make
if [ $2 ]; then
    TAPELEN=$2
else
    TAPELEN=10
fi

# find dir script is located in
DIR="$( cd -P "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
$DIR/elf_bf_compiler ../demo/demo demo $1 $TAPELEN demo.debug
