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

#ifndef __SYMTAB_H
#define __SYMTAB_H

#include <libelfsh.h>


typedef struct {
  elfsh_Sym *sym;
  eresi_Addr addr;
  eresi_Addr index;
} elf_bf_Sym;

typedef struct {
  int lm_allocated;
  elfshobj_t *lm_f;
  char *lm_out_name;
  elfshsect_t *lm_reloc;
  elfshsect_t *lm_sym;
  elf_bf_Sym *lm_ifunc;
  eresi_Addr lm_ifunc_addr; //address of machine code that returns zero
  eresi_Addr lm_l_addr;
  eresi_Addr lm_l_s; //address of own link map
  eresi_Addr lm_l_o; //address of partner's link map
  eresi_Addr lm_next_reloc; //next reloc entry to be filled in
  eresi_Addr lm_bss_index; //index of bss section's shdr TODO: I dont think we use this anymore

} elf_bf_link_map_t;


elfshsect_t *symtab_get_sym_shsect(elfshobj_t *f, char *name);
void symtab_get_sym(elf_bf_link_map_t *l, eresi_Addr index, elf_bf_Sym *s);
eresi_Addr symtab_get_sym_addr(elfshsect_t *sec, eresi_Addr index);
void symtab_set_sym(elf_bf_Sym *sym, eresi_Addr size, eresi_Addr value, eresi_Addr type);
eresi_Addr symtab_get_value_addr(elf_bf_Sym *sym);
eresi_Addr symtab_get_link_addr(elf_bf_Sym *sym);
eresi_Addr symtab_get_index(elf_bf_Sym *sym);
#endif //ifndef __SYMTAB_H
