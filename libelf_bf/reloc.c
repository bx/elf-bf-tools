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
#include "reloc.h"

elfshsect_t *reloc_get_reloc_shsect(elfshobj_t *f, char *name)
{
  return elfsh_get_section_by_name(f,name, NULL, NULL, NULL);
}

void reloc_get_reloc_entry(elf_bf_link_map_t *lm, eresi_Addr index, elf_bf_Rela *rel)
{
  // they do something like this in their code, but it doesn't actually work
  // with rela entries, I get off by (size of addend) errors when I get the
  // rela entries this way
  //rel->rel = (elfsh_Rela *) elfsh_get_relent_by_index(sec->data, index);

  if (lm->lm_allocated) {
    elfshsect_t *sec = lm->lm_reloc;
    rel->rel = ((elfsh_Rela *) sec->data) + index;
    rel->addr = (eresi_Addr) (((elfsh_Rela *) sec->shdr->sh_addr) + index);
  } else {
    rel->rel = NULL;
    rel->addr = 0;
  }
}

eresi_Addr reloc_get_addr(elf_bf_Rela *r)
{
  if (r) {
    return r->addr;
  } else{
    return 0;
  }
}

//the elfsh_set_rel* functions work on Rels, these are so I can avoid type casting all the time
void reloc_set_relatype(elf_bf_Rela *r, Elf64_Word type)
{
  if (r->rel) {
    elfsh_set_reltype((elfsh_Rel *) r->rel, type);
  }
}

void reloc_set_relasym(elf_bf_Rela *r, Elf64_Word sym)
{
  if (r->rel) {
    elfsh_set_relsym((elfsh_Rel *) r->rel, sym);
  }
}

void reloc_set_relaoffset(elf_bf_Rela *r, Elf64_Addr off)
{
  if (r->rel) {
    elfsh_set_reloffset((elfsh_Rel *) r->rel, off);
  }
}

void reloc_set_reladdend(elf_bf_Rela *r, Elf64_Addr val){
  if (r->rel) {
    elfsh_set_reladdend(r->rel,val);
  }
}


void reloc_set_rela(elf_bf_Rela *r, Elf64_Word type, Elf64_Word sym, Elf64_Addr off, Elf64_Addr val)
{
  if (r->rel) {
    reloc_set_relatype(r,type);
    reloc_set_relasym(r, sym);
    reloc_set_relaoffset(r, off);
    reloc_set_reladdend(r, val);
  }
}


eresi_Addr reloc_get_offset_addr(elf_bf_Rela *rel)
{
  if (rel && (rel->addr)) {
    return (eresi_Addr) &(((Elf64_Rela *)rel->addr)->r_offset);
  } else {
    return 0;
  }
}

eresi_Addr reloc_get_offset(elf_bf_Rela *rel)
{
  if (rel && (rel->rel)) {
    return rel->rel->r_offset;
  } else {
    return 0;
  }
}
eresi_Addr reloc_get_addend_addr(elf_bf_Rela *rel)
{
  if (rel && (rel->addr)) {
    return (eresi_Addr) &(((Elf64_Rela *)rel->addr)->r_addend);
  } else {
    return 0;
  }
}
eresi_Addr reloc_get_symnum_addr(elf_bf_Rela *rel)
{
  if (rel && (rel->addr)) {
    return (eresi_Addr) &(((Elf64_Rela *)rel->addr)->r_info) + 4;
  } else {
    return 0;
  }
}
