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

#include <libelfsh.h>
#include "symtab.h"

elfshsect_t *symtab_get_sym_shsect(elfshobj_t *f, char *name)
{
  return elfsh_get_section_by_name(f,name, NULL, NULL, NULL);
}


void symtab_get_sym(elf_bf_link_map_t *l, eresi_Addr index, elf_bf_Sym *s)
{
  if (l->lm_allocated) {
    elfshsect_t *sec = l->lm_sym;
    s->sym = ((elfsh_Sym *) sec->data) + index;
    s->addr = symtab_get_sym_addr(sec,index);
    s->index = index;
  }
}

eresi_Addr symtab_get_sym_addr(elfshsect_t *sec, eresi_Addr index)
{
  if (sec) {
    return (eresi_Addr) (((elfsh_Sym *) sec->shdr->sh_addr) + index);
  }else{
    return 0;
  }
}

void symtab_set_sym(elf_bf_Sym *sym, eresi_Addr size, eresi_Addr value, eresi_Addr type)
{
  elfsh_set_symbol_size(sym->sym,size);
  elfsh_set_symbol_value(sym->sym,value);
  elfsh_set_symbol_type(sym->sym,type);
}


eresi_Addr symtab_get_value_addr(elf_bf_Sym *sym)
{
  if (sym) {
    return (eresi_Addr) &(((Elf64_Sym *)sym->addr)->st_value);
  } else {
    return 0;
  }
}
eresi_Addr symtab_get_index(elf_bf_Sym *sym)
{
  if (sym) {
    return sym->index;
  } else {
    return 0;
  }
}
eresi_Addr symtab_get_link_addr(elf_bf_Sym *sym)
{
  if (sym) {
    return (eresi_Addr) &(((Elf64_Sym *)sym->addr)->st_shndx);
  } else {
    return 0;
  }
}
