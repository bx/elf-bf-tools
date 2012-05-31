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

#define INPUT_FILE "../demo/demo"
#define OUTPUT_FILE "demo"

#define TAPE_LEN 10

void create_relas();

int main(int argv, char *argc[])
{
  if (argv != 2) {
    fprintf(stderr, "usage: %s <brainfuck source file>\n",argc[0]);
    exit(-1);
  }


  elf_bf_env_t e;
  elfutils_setup_env(argc[1],INPUT_FILE,OUTPUT_FILE,
		     TAPE_LEN,
		     0x5555555688dc, /*ifunc .. __sigsetjmp*/
		     0x555555773220, /*exec l*/
		     0x7fffffffd9b0, /*exec reloc end*/
		     0x600f28, /* location of dt_rela */
		     0x600f38, /* location of dt_relasz */
		     0x600ea8, /* location of dt_sym */
		     0x600f18, /* location of dt_jumprel */
		     0x601ef8, /* location of dt_pltrelsz */
		     &e);
  compile_bf_instructions(&e);

  elfutils_save_env(&e);
  return 0;
}
