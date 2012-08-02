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
#include <elf.h>
#include <stdlib.h>
#include <stdio.h>
#include <libelfsh.h>
#include "elf_bf_utils.h"
#include "elf_bf_ops.h"
#include "elf_reloc_utils.h"
#include "reloc.h"
#include "symtab.h"

void init_tape_pointer(elf_bf_exec_t *env);
void init_tape_syms(elf_bf_exec_t *env);
void init_elf_bf_linkmap(elf_bf_link_map_t *l, char *in, char *out);
void fix_dynamic_table(elf_bf_exec_t *env);
void insert_exec_secs(elf_bf_exec_t *env);
void elfutils_save_lm(elf_bf_link_map_t *l);
void init_exec_tape_pointer(elf_bf_exec_t *env);
void init_exec_branch_syms(elf_bf_exec_t *ee);
unsigned long process_bf_instructions (elf_bf_env_t *e, int countonly, size_t start, size_t end);
unsigned long bf_rela_count(elf_bf_env_t *e);
char *read_source(char *file);
void fixup_branch_start(elf_bf_exec_t *ee, size_t index, size_t diff, size_t afterend);
size_t find_branch_start(size_t pos, char *instructions);
void elfutils_setup_env(char *src,
			char *execf_in,
			char *execf_out,
			int tape_len,
			eresi_Addr ifuncoffset,
			eresi_Addr dl_auxv, // offset of _dl_auxv (in ld.so's data)
			eresi_Addr endoffset, // offset of &end on stack from where auxv lives on stack (value of _dl_auxv)
			int debug,
			elf_bf_env_t *env)
{
  elfsh_Dyn *dyn;
  // open and load exec
  env->e_bf_source = read_source(src);
  env->e_bf_sourcepath = src;
  env->e_exec.ee_ifunc_offset = ifuncoffset;
  env->e_exec.ee_dl_auxv = dl_auxv;
  env->e_exec.ee_end_offset = endoffset;
  env->e_exec.ee_for_debug = debug;
  init_elf_bf_linkmap(&(env->e_exec.ee_lm), execf_in, execf_out);
  elfshsect_t *bs; //we will pretend this section is our string table
  bs = elfsh_get_section_by_name(env->e_exec.ee_lm.lm_f, ".bss", NULL, NULL, NULL);
  env->e_exec.ee_lm.lm_bss_index = bs->index;
  env->e_exec.ee_tape_len = tape_len;
  //env->e_exec.ee_reloc_end = exec_reloc_end;
  env->e_exec.ee_dt_rela =  get_dynent_addr(env->e_exec.ee_lm.lm_f, DT_RELA);
  env->e_exec.ee_dt_relasz = get_dynent_addr(env->e_exec.ee_lm.lm_f, DT_RELASZ);
  env->e_exec.ee_dt_sym =  get_dynent_addr(env->e_exec.ee_lm.lm_f, DT_SYMTAB);
  env->e_exec.ee_dt_jmprel =  get_dynent_addr(env->e_exec.ee_lm.lm_f, DT_JMPREL);
  env->e_exec.ee_dt_pltrelsz = get_dynent_addr(env->e_exec.ee_lm.lm_f, DT_PLTRELSZ);

  env->e_exec.ee_ptr_tape_ptr = NULL;
  env->e_exec.ee_tape_ptr = NULL;
  env->e_exec.ee_ptr_tape_copy = NULL;
  env->e_exec.ee_lm.lm_ifunc = NULL;
  env->e_exec.ee_exec_map = NULL;
  env->e_exec.ee_stack_addr = NULL;



  env->e_exec.ee_num_reloc = bf_rela_count(env);
  init_tape_syms(&(env->e_exec)); //first count number of new syms
  insert_exec_secs(&(env->e_exec));
  init_tape_syms(&(env->e_exec));
  fix_dynamic_table(&(env->e_exec));
}

elfshobj_t *elfutils_read_elf_file(char *file)
{
  elfshobj_t *eo = elfsh_map_obj(file);
  if (!(eo)) {
    elfsh_error();
    fprintf(stderr,"ERROR");
    exit(-1);
  }
  return eo;
}
void init_elf_bf_linkmap(elf_bf_link_map_t *l, char *in, char *out)
{
  l->lm_allocated = 0;
  l->lm_f = elfutils_read_elf_file(in);
  l->lm_out_name = out;
  //l->lm_ifunc_addr = ifunc;
  l->lm_next_reloc = 0;
}

void fix_dynamic_table(elf_bf_exec_t *env)
{
  elfsh_Dyn *dyn;
  elfshobj_t *f = env->ee_lm.lm_f;

  dyn = elfsh_get_dynamic_entry_by_type(f, DT_RELA);
  env->ee_rela_orig = elfsh_get_dynentry_val(dyn);
  elfsh_set_dynentry_val(dyn, elfsh_get_section_addr(env->ee_lm.lm_reloc->shdr));
  dyn = elfsh_get_dynamic_entry_by_type(f, DT_RELASZ);
  env->ee_relasz_orig = elfsh_get_dynentry_val(dyn);
  elfsh_set_dynentry_val(dyn, elfsh_get_section_size(env->ee_lm.lm_reloc->shdr));
  env->ee_dt_relasz_value = elfsh_get_section_size(env->ee_lm.lm_reloc->shdr);
  env->ee_reloc_end_value = elfsh_get_section_addr(env->ee_lm.lm_reloc->shdr) + env->ee_dt_relasz_value;
  dyn = elfsh_get_dynamic_entry_by_type(f, DT_GNU_HASH);
  env->ee_dt_gnu_hash = elfsh_get_dynentry_val(dyn);
  dyn = elfsh_get_dynamic_entry_by_type(f, DT_SYMTAB);
  env->ee_sym_orig = elfsh_get_dynentry_val(dyn);
  elfsh_set_dynentry_val(dyn, elfsh_get_section_addr(env->ee_lm.lm_sym->shdr));


  dyn = elfsh_get_dynamic_entry_by_type(f, DT_JMPREL);
  env->ee_dt_jmprel_value = elfsh_get_dynentry_val(dyn);
  elfsh_set_dynentry_val(dyn, 0);

  dyn = elfsh_get_dynamic_entry_by_type(f, DT_PLTRELSZ);
  env->ee_dt_pltrelsz_value = elfsh_get_dynentry_val(dyn);
  elfsh_set_dynentry_val(dyn, 0);

  //dyn = elfsh_get_dynamic_entry_by_type(f, DT_SYMENT);
  //env->ee_sym_orig = elfsh_get_dynentry_val(dyn);
}
unsigned long bf_rela_count(elf_bf_env_t *e)
{
  return process_bf_instructions(e,1,0,0);
}
void compile_bf_instructions(elf_bf_env_t *e)
{
  process_bf_instructions(e,0,0,0);
}

char *read_source(char *file)
{
  FILE *f;
  size_t s;
  char *src;
  f = fopen(file,"r");
  //look up file size
  fseek(f, 0L, SEEK_END);
  s = ftell(f);
  fseek(f, 0L, SEEK_SET);

  src = (char *) malloc(sizeof(char) * (s+1));

  //read file
  size_t pc;
  for (pc = 0; (src[pc] = fgetc(f)) != EOF; pc++) {}
  src[pc] = 0;
  printf("\"%s\"",src);
  fclose(f);
  return src;
}
void fixup_branch_start(elf_bf_exec_t *ee, size_t index, size_t diff, size_t afterend)
{
  //diff is the number of rela instructions between the start of the
  //first branch statement and the start of the last branch
  elf_bf_Rela r0, r1, next;
  elf_bf_link_map_t *lm = &(ee->ee_lm);
  //index of first entry in ']'
  reloc_get_reloc_entry(lm, (index) - (diff+4), &r0);
  reloc_get_reloc_entry(lm, (index) - (diff+3), &r1);
  reloc_get_reloc_entry(lm, afterend, &next);
  reloc_set_reladdend(&r0, next.addr);
  reloc_set_reladdend(&r1, ee->ee_dt_relasz_value - (afterend * sizeof(Elf64_Rela)));
}
void fixup_branch_end(elf_bf_exec_t *ee, size_t index, size_t diff)
{
  //diff is the number of rela instructions between the start of the
  //first branch statement and the start of the last branch
  elf_bf_Rela r0, r1, jump;
  elf_bf_link_map_t *lm = &(ee->ee_lm);
  reloc_get_reloc_entry(lm, index, &r0);
  reloc_get_reloc_entry(lm, index+1, &r1);
  reloc_get_reloc_entry(lm, index-diff, &jump);
  reloc_set_reladdend(&r0, jump.addr);
  reloc_set_reladdend(&r1,ee->ee_dt_relasz_value - ((index-diff) * sizeof(Elf64_Rela)));
}
size_t find_branch_start(size_t pos, char *instructions)
{
  size_t level = 1;
  for (pos = pos - 1; pos >= 0; pos--) {
    if (instructions[pos] == ']') {
	level++;
    }else if (instructions[pos] == '[') {
      level--;
      if (level == 0){
	break;
      }
    }
  }
  if ((0 == pos) && ('[' != instructions[pos])) {
    fprintf(stderr,"mismatched brackets\n");
  }
  return pos;
}

unsigned long process_bf_instructions (elf_bf_env_t *e, int countonly, size_t start, size_t end)
{
  size_t i = 0;
  char c;
  unsigned long count = 0;
  elf_bf_exec_t *ee = &(e->e_exec);
  eresi_Addr next_reloc = ee->ee_lm.lm_next_reloc;
  int allocated = ee->ee_lm.lm_allocated;
  unsigned long oldcount;
  if (countonly) {
    ee->ee_lm.lm_allocated = 0;
    ee->ee_lm.lm_next_reloc = 0;
  }else{
    start = 0;
    end = 0;

  }
  if (end == 0) { //only if we are totaling everything
    count += init_scatch_space(ee);
  }
  //if end == 0, then count until the end
  //printf("start %d, count %d, end %d\n", start, count, end);

  for (i=start; ((c = e->e_bf_source[i]) != 0) && ((end==0) || (i<end));
       i++) {
    //printf("count  %d before '%c'\n", count, c);
    switch (c) {
    case '+':
      count = count+elfops_increment(ee);
      break;
    case '-':
      count = count+elfops_decrement(ee);
      break;
    case '>':
      count = count+elfops_increment_ptr(ee);
      break;
    case '<':
      count = count+elfops_decrement_ptr(ee);
      break;
    case '[':
      count = count+elfops_branch_start(ee);
      break;
    case ']':
      oldcount = count;
      count = count+elfops_branch_end(ee);
      if (! countonly) {
	start = find_branch_start(i,e->e_bf_source);
	size_t diff;
	diff = process_bf_instructions(e,1,start+1,i);
	//printf("diff %d, start %d, i %d\n", diff, start, i);
	fixup_branch_start(ee,oldcount,diff, count);
	diff = process_bf_instructions(e,1,start, i);
	fixup_branch_end(ee,oldcount,diff);
      }
      break;
    case 'X':
      count = count+elfops_exit(ee);
    case '\n':
    case '\r':
    case '\t':
    case ' ':
      break;
    default:
      fprintf(stderr,"unrecognized bf symbol: %c", c);
      exit(-1);
    }
  }

  if (countonly) {
    //printf("%lu instructions\n",count);
    ee->ee_lm.lm_next_reloc = next_reloc;
    ee->ee_lm.lm_allocated = allocated;
  }
  return count;
}

elfshsect_t *insert_reloc_sec(elfshobj_t *f, eresi_Addr numrel, elfshsect_t *newsym)
{
  char *rels;
  elfsh_Shdr *hdrrel;
  elfshsect_t *newrel;


  //alloc space for new sections
  rels = (char *) calloc(numrel, sizeof(Elf64_Rela));
  hdrrel = (elfsh_Shdr *) calloc(1, sizeof(elfsh_Shdr));


  /* Create the section descriptor (ESD) */
  newrel = elfsh_create_section(".rela.p");
  if (!newrel) {
    elfsh_error();
    exit(-1);
  }

  /* Create a section header for the mapped section */
  *hdrrel = elfsh_create_shdr(0, SHT_RELA, SHF_WRITE | SHF_ALLOC, 0, 0, numrel*sizeof(Elf64_Rela), newsym->index, 0, 8, sizeof(Elf64_Rela));

  if (elfsh_insert_data_section(f, newrel, *hdrrel, rels) < 0) {
   elfsh_error();
   exit(-1);
  }

  /* Retreive it again since the file offset and the vaddr may have been updated during insertion */
  newrel = elfsh_get_section_by_name(f, ".rela.p", NULL, NULL, NULL);
  if (!newrel) {
    elfsh_error();
    exit(-1);
  }


  return newrel;
}

elfshsect_t *insert_symtab_sec(elfshobj_t *f, eresi_Addr numsym, eresi_Addr strtab)
{
  char *syms;
  elfsh_Shdr *hdrsym;
  elfshsect_t *newsym;

  syms = (char *) calloc(numsym, sizeof(Elf64_Sym));
  hdrsym = (elfsh_Shdr *) calloc(1, sizeof(elfsh_Shdr));

  newsym = elfsh_create_section(".sym.p");
  if (!newsym) {
    elfsh_error();
    exit(-1);
  }

  /* Create a section header for the mapped section for a string table*/
  *hdrsym = elfsh_create_shdr(0, SHT_SYMTAB, SHF_WRITE | SHF_ALLOC, 0, 0, numsym*sizeof(Elf64_Sym), strtab, 2, 8, sizeof(Elf64_Sym));

  if (elfsh_insert_data_section(f, newsym, *hdrsym, syms) < 0) {
    elfsh_error();
    exit(-1);
  }


  /* Retreive it again since the file offset and the vaddr may have been updated during insertion */
  newsym = elfsh_get_section_by_name(f, ".sym.p", NULL, NULL, NULL);
  elfsh_set_section_type(newsym->shdr, SHT_DYNSYM);
  if (!newsym) {
    elfsh_error();
    exit(-1);
  }


  return newsym;
}

void copy_dynrel(elf_bf_exec_t *ee)
{
  // get a copy of the current reladyn section so we can
  // copy data at end
  elfshsect_t *dynrel, *newrel;
  dynrel = elfsh_get_section_by_name(ee->ee_lm.lm_f, ".rela.dyn", NULL, NULL, NULL);
  newrel = ee->ee_lm.lm_reloc;
  // copy original relocation entries at end
  memcpy((void *) (newrel->data) + (ee->ee_num_reloc*sizeof(Elf64_Rela)), dynrel->data, elfsh_get_section_size(dynrel->shdr));
}
void copy_dynsym(elf_bf_exec_t *ee)
{
  //get original symbol table
  elfshsect_t *dynsym;
  dynsym = elfsh_get_section_by_name(ee->ee_lm.lm_f, ".dynsym", NULL, NULL, NULL);

 // copy in dynsym symbols
  ee->ee_lm.lm_sym->data = memcpy(ee->ee_lm.lm_sym->data, dynsym->data, elfsh_get_section_size(dynsym->shdr));

}
void insert_exec_secs(elf_bf_exec_t *env)
{
  elfshsect_t *sec, *str;
  sec = elfsh_get_section_by_name(env->ee_lm.lm_f, ".dynsym", NULL, NULL, NULL);

  //str = elfsh_get_section_by_name(env->ee_lm.lm_f, ".dynstr", NULL, NULL, NULL);
  env->ee_num_orig_syms = elfsh_get_section_size(sec->shdr)/sizeof(Elf64_Sym);
  env->ee_num_used_syms = env->ee_num_orig_syms;

  env->ee_lm.lm_sym = insert_symtab_sec(env->ee_lm.lm_f, env->ee_num_new_syms + env->ee_num_used_syms  + env->ee_tape_len, elfsh_get_section_link(sec->shdr));
  elfsh_set_section_type(sec->shdr, SHT_NULL);

  copy_dynsym(env);
  sec = elfsh_get_section_by_name(env->ee_lm.lm_f, ".rela.dyn", NULL, NULL, NULL);
  env->ee_lm.lm_reloc = insert_reloc_sec(env->ee_lm.lm_f, env->ee_num_reloc + (elfsh_get_section_size(sec->shdr)/sizeof(Elf64_Rela)), env->ee_lm.lm_sym);
  copy_dynrel(env);
  env->ee_lm.lm_allocated = 1;
}

void elfutils_save_elf_file(elfshobj_t *o, char *file)
{

  int ret = elfsh_save_obj(o, file);
  if (ret < 0){
    elfsh_error();
  }
}

void elfutils_save_lm(elf_bf_link_map_t *l)
{
  //write, read, and write to fix headers
  elfutils_save_elf_file(l->lm_f,l->lm_out_name);

}

void elfutils_save_env(elf_bf_env_t *env)
{

  //profiler_enable_err();
  //profiler_install(printf,printf);

  elfutils_save_lm(&(env->e_exec.ee_lm));
}

//just cont number of symbols if lm_allocated is false
void init_tape_syms(elf_bf_exec_t *env)
{

  elf_bf_Sym *sym, *psym, *ifunc, *execmap, *ptrtapecpy, *stackaddr;
  elf_bf_Sym top;
  if (env->ee_lm.lm_allocated){
    psym = calloc(1, sizeof(elf_bf_Sym));
    sym = calloc(1, sizeof(elf_bf_Sym));
    ptrtapecpy = calloc(1, sizeof(elf_bf_Sym));
    ifunc = calloc(1, sizeof(elf_bf_Sym));
    execmap = calloc(1, sizeof(elf_bf_Sym));
    stackaddr = calloc(1, sizeof(elf_bf_Sym));
  }
  eresi_Addr index = env->ee_num_used_syms;
  //index++;
  //printf("index: %d\n", index);
  //symtab_get_sym(&(env->ee_lm), index++, nsym);
  symtab_get_sym(&(env->ee_lm), index++, psym);
  symtab_get_sym(&(env->ee_lm), index++, sym);
  symtab_get_sym(&(env->ee_lm), index++, ifunc);
  symtab_get_sym(&(env->ee_lm), index++, ptrtapecpy);
  symtab_get_sym(&(env->ee_lm), index++, execmap);
  symtab_get_sym(&(env->ee_lm), index, stackaddr);
  if (env->ee_lm.lm_allocated){
    env->ee_num_used_syms = index;

    symtab_get_sym(&(env->ee_lm), index+1, &top);

    //keeps the tape head symbol number

    //address of where tape head is pointing's value
    symtab_set_sym(psym, 1, top.addr, STT_FUNC);

    //assume tape head value is zero
    symtab_set_sym(sym, 1, 0, STT_FUNC);
    symtab_set_sym(ifunc, 8, 0, STT_GNU_IFUNC);
    //elfsh_set_symbol_link(ifunc->sym, 1);
    symtab_set_sym(ptrtapecpy, 1, symtab_get_value_addr(sym), STT_FUNC);

    //start it up with address of PLTGOT
    elfsh_Dyn *dyn;
    eresi_Addr pltgot;
    dyn = elfsh_get_dynamic_entry_by_type(env->ee_lm.lm_f, DT_PLTGOT);
    pltgot = elfsh_get_dynentry_val(dyn);
    env->ee_dt_pltgot = pltgot+8;
    symtab_set_sym(execmap, 8, pltgot+8, STT_FUNC);


    symtab_set_sym(stackaddr, 8, 0, STT_FUNC);

    //env->ee_tape_symnum = psym->index;
    env->ee_ptr_tape_ptr = psym;
    env->ee_tape_ptr = sym;
    env->ee_lm.lm_ifunc = ifunc;
    env->ee_ptr_tape_copy = ptrtapecpy;
    env->ee_exec_map = execmap;
    env->ee_stack_addr = stackaddr;
  }
  env->ee_num_new_syms = index - env->ee_num_used_syms;
}


void fixup_dynamic_rela(elfshobj_t *f, eresi_Addr rel, eresi_Addr sz)
{
  elfsh_Dyn *dyn;
  dyn = elfsh_get_dynamic_entry_by_type(f, DT_RELA);
  elfsh_set_dynentry_val(dyn, rel);
  dyn = elfsh_get_dynamic_entry_by_type(f, DT_RELASZ);
  elfsh_set_dynentry_val(dyn, sz);

}

void fixup_dynamic_sym(elfshobj_t *f, eresi_Addr sym, eresi_Addr sz)
{
  elfsh_Dyn *dyn;
  dyn = elfsh_get_dynamic_entry_by_type(f, DT_SYMTAB);
  elfsh_set_dynentry_val(dyn, sym);
  //dyn = elfsh_get_dynamic_entry_by_type(f, DT_RELASZ);
  //elfsh_set_dynentry_val(dyn, sz);

}

eresi_Addr set_next_reloc(elf_bf_link_map_t *l, Elf64_Word type, Elf64_Word sym, Elf64_Addr off, Elf64_Addr val)
{
  if(l->lm_allocated) {
    elf_bf_Rela r;
    reloc_get_reloc_entry(l, l->lm_next_reloc, &r);
    reloc_set_rela(&r, type, sym, off, val);
  } //otherwise just count
  l->lm_next_reloc++;
  return l->lm_next_reloc - 1;
}
