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

// functions to make my life easier when reading/writing relocation entries

#ifndef __RELOC_H
#define __RELOC_H

#include <libelfsh.h>
#include "symtab.h"

typedef struct {
  elfsh_Rela *rel;
  eresi_Addr addr;
} elf_bf_Rela;


// get relocation section from elfshobj_t by name (elfshobj_t) -> elfshsect_t
elfshsect_t *reloc_get_reloc_shsect(elfshobj_t *f, char *name);

// get relocation entry (reloaction section, index) -> rel entry
void reloc_get_reloc_entry(elf_bf_link_map_t *lm, eresi_Addr index, elf_bf_Rela *rel);

//the elfsh_set_rel* functions work on Rels, these are so I can avoid type casting all the time
void reloc_set_relatype(elf_bf_Rela *r, Elf64_Word type);
void reloc_set_relasym(elf_bf_Rela *r, Elf64_Word sym);
void reloc_set_relaoffset(elf_bf_Rela *r, Elf64_Addr off);
void reloc_set_reladdend(elf_bf_Rela *r, Elf64_Addr val);
void reloc_set_rela(elf_bf_Rela *r, Elf64_Word type, Elf64_Word sym, Elf64_Addr off, Elf64_Addr val);
eresi_Addr reloc_get_offset_addr(elf_bf_Rela *rel);
eresi_Addr reloc_get_addend_addr(elf_bf_Rela *rel);
eresi_Addr reloc_get_symnum_addr(elf_bf_Rela *rel);
eresi_Addr reloc_get_addr(elf_bf_Rela *r);

#endif //ifdef __RELOC_H
