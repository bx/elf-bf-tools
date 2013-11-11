/* Copyright (c) 2012 Rebecca (bx) Shapiro

   Permission is hereby granted, free of charge, to any person obtaining a copy
   of this software and associated documentation files (the "Software"), to deal
   in the Software without restriction, including without limitation the rights
   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
   copies of the Software, and to permit persons to whom the Software is
   furnished to do so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included in all
   copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
   SOFTWARE.
*/

#include <stdio.h>
#include "elf_bf_utils.h"
#include "elf_bf_debug_config.h"
void create_relas();

//to make it work with anything, we need to also configure
// the number of hops in the linkmap structure
// to get to exec/ld's link map
int main(int argv, char *argc[])
{

  if ((argv < 5)){
    fprintf(stderr, "usage: %s <input exec> <out name> <brainfuck source file> <offset of &end to _dl_auxv>  <where to write debugging information> <tape length>\n",argc[0]);
    exit(-1);
  }

  char *inexec, *outexec, *bf, *config;
  unsigned int tapelen = atoi(argc[6]);
  int debug;
  eresi_Addr ifunc = 0x148dc;
  eresi_Addr auxv = 0x21de28;
  //eresi_Addr end = -0x408; //or -x428? 
  //eresi_Addr end = -0x388; //or -x428? 
  //eresi_Addr end = -0x428; // gdb
  eresi_Addr end = -0x3f8; // no gdb
  //eresi_Addr end = -0x378; // ddd
  inexec = argc[1];
  outexec = argc[2];
  bf = argc[3];
  end = strtol(argc[4], NULL, 16);

  debug = 1;
  config = argc[5];


  int max = 256;
  char libc[max];
  char ld[max];
  lookup_ld_path(inexec, ld, max);
  lookup_libc_path(inexec, libc, max);
  auxv = dl_auxv_offset(ld);
  ifunc = ret0_offset(ld);
  elf_bf_env_t e;
  elfutils_setup_env(bf, inexec, outexec, libc, tapelen,
		     ifunc, auxv, end, debug,
		     &e);
  compile_bf_instructions(&e);
  elfutils_save_env(&e);
  if ( NULL != debug ) {
    elf_bf_write_debug(&e, config);
  }
  
  return 0;
}
