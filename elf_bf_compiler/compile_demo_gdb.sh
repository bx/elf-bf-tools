#!/bin/bash

make
if [ $2 ]; then
    TAPELEN=$2
else
    TAPELEN=10
fi

gdb --args  elf_bf_compiler ../demo/demo demo $1 $TAPELEN demo.debug
