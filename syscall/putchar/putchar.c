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
#include <libaspect.h>
#define NUM_RELOC 100
#define RET 0xc3

// returns the location of a ret in the text segment
void insert_putchar(char c, elf_bf_link_map_t *l, elf_bf_Sym *got);
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


eresi_Addr get_putchar_offset(char *libc)
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
    if(strcmp("putchar", cmpname) == 0){
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
  elf_bf_Sym got, copy;
  eresi_Addr sz, ret;
  //elf_bf_Rela r[NUM_RELOC];
  eresi_Addr i;
  char *input, *output, *libc;
  
  if (argv != 4) {
    fprintf(stderr, "recieved %d args, usage: %s <input> <output name> <path to libc>\n", argv, argc[0]);
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
  elfsh_Rela *exit = NULL;
  elf_bf_Rela first;

  elf_bf_Rela irel, setrel;//, exitr;
  eresi_Addr irel_addr, setrel_addr;//, exitr_addr;
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



  set_next_reloc(&l, R_X86_64_64, got.index, symtab_get_value_addr(&got), get_putchar_offset(libc));//adds offset of exit to libc base addr, stores in symbol's value

  printf("&putchar: %x\n", get_putchar_offset(libc));
  insert_putchar('I', &l, &got);
  insert_putchar('\'', &l, &got);
  insert_putchar('m', &l, &got);
  insert_putchar(' ', &l, &got);
  insert_putchar('i', &l, &got);
  insert_putchar('n', &l, &got);
  insert_putchar(' ', &l, &got);
  insert_putchar('y', &l, &got);
  insert_putchar('e', &l, &got);
  insert_putchar('r', &l, &got);
  insert_putchar(' ', &l, &got);
  insert_putchar('e', &l, &got);
  insert_putchar('l', &l, &got);
  insert_putchar('f', &l, &got);
  insert_putchar('\n', &l, &got);
  //ret = find_ret_loc(l.m_f); // find a location of a ret instruction in ping's binary
  //printf("Found a ret at %x\n", ret);

  //set_next_reloc(&l, R_X86_64_COPY, got.index, reloc_get_addr(&setrel), 0); //set rdi
  //irel_addr = set_next_reloc(&l, R_X86_64_IRELATIVE, 0,reloc_get_addr(&setrel),0); //call ifunc . addend is filled in at runtime. result stored at setrel_addr
  //set_next_reloc(&l, R_X86_64_COPY, got.index, reloc_get_addr(&setrel), 0); //set rdi
  //irel_addr = set_next_reloc(&l, R_X86_64_IRELATIVE, 0,reloc_get_addr(&setrel),0); //call ifunc . addend is filled in at runtime. result stored at setrel_addr
  //set_next_reloc(&l, R_X86_64_COPY, got.index, reloc_get_addr(&setrel), 0); //set rdi
  //irel_addr = set_next_reloc(&l, R_X86_64_IRELATIVE, 0,reloc_get_addr(&setrel),0); //call ifunc . addend is filled in at runtime. result stored at setrel_addr

  //set_next_reloc(&l, R_X86_64_TLSDESC, got.index, reloc_get_offset_addr(&setrel), 0);  //this will cause a floating point exception

  aspect_init();
  aspectworld.profile = printf;
  aspectworld.profile_err = printf;

  //profiler_enable_err();
  elfutils_save_elf_file(l.lm_f, output);
 
  return 0;
}


void insert_putchar(char c, elf_bf_link_map_t *l, elf_bf_Sym *got) {
  elf_bf_Rela irel, setrel;//, exitr;
  eresi_Addr irel_addr, setrel_addr;//, exitr_addr;
  setrel_addr = set_next_reloc(l, R_X86_64_64, got->index,0, 0); // set irel's addend to addr of putchar
  reloc_get_reloc_entry(l, setrel_addr, &setrel);
  
  // change size of 0th symbol
  set_next_reloc(l, R_X86_64_RELATIVE, 0, 
		 symtab_get_value_addr(got)+8, 0);
  eresi_Addr v = reloc_get_addr(&setrel);
  v = v & 0xFFFF00;
  v += c;
 set_next_reloc(l, R_X86_64_COPY, got->index, v, 0); //set RDI value (first argument)
  irel_addr = set_next_reloc(l, R_X86_64_IRELATIVE, 0,reloc_get_addr(&setrel),0); //call ifunc . addend is filled in at runtime. result stored at setrel_addr
  reloc_get_reloc_entry(l, irel_addr, &irel);
  reloc_set_relaoffset(&setrel, reloc_get_addend_addr(&irel)); //tell exit to write putchar addr to IRELATIVE entry

}
