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

#ifndef __ELF_BF_UTILS_H
#define __ELF_BF_UTILS_H
#include "symtab.h"
#include "elf_bf_link_map.h"

typedef struct {
  elf_bf_link_map_t ee_lm;
  //eresi_Addr ee_tape_symnum;
  elf_bf_Sym *ee_ptr_tape_ptr; //points to current tape value
  elf_bf_Sym *ee_ptr_tape_copy; //holds address of where tape head pointer (ee_tape_ptr's value)
  elf_bf_Sym *ee_tape_ptr; //tape head pointer, copy  of value is the address of the current tape value
  elf_bf_Sym *ee_branch_location; //address of instructions that return 0
  //elf_bf_Sym *ee_tape_copy; //copy of value tape is pointing to
  elf_bf_Sym *ee_exec_map; //eventually holds address of exec's link_map
  elf_bf_Sym *ee_ld_base; //eventually holds base address of ld
  elf_bf_Sym *ee_stack_addr; //eventaully holds address of known item on stack
  //elf_bf_Sym *ee_scratch_space; //scratch space for calculations

  unsigned int ee_tape_len;
  unsigned int ee_num_used_syms;
  unsigned int ee_num_orig_syms;
  unsigned int ee_num_new_syms;
  unsigned int ee_num_reloc;
  eresi_Addr ee_dt_rela;
  eresi_Addr ee_dt_relasz;
  eresi_Addr ee_dt_relasz_value;
  eresi_Addr ee_dt_sym;
  //eresi_Addr ee_lib_dt_relasz;
  eresi_Addr ee_reloc_end_value; // normal value of end
  elfsh_Word ee_rela_orig;
  elfsh_Word ee_relasz_orig;
  eresi_Addr ee_dt_jmprel;
  eresi_Addr ee_dt_jmprel_value;
  eresi_Addr ee_dt_pltrelsz;
  eresi_Addr ee_dt_pltgot;
  eresi_Addr ee_dt_pltrelsz_value;

  //elfsh_Word ee_relacount_orig;
  elfsh_Word ee_sym_orig;
  eresi_Addr ee_dt_gnu_hash; //GNU_HASH entry in dynamic table
} elf_bf_exec_t;

typedef struct {
  char *e_bf_source;
  char *e_bf_sourcepath;
  elf_bf_exec_t e_exec;
} elf_bf_env_t;


void elfutils_setup_env(char *src,
                        char *execf_in,
                        char *execf_out,
                        int tape_len,
                        eresi_Addr ifunc,
                        elf_bf_env_t *env);

void elfutils_save_env (elf_bf_env_t *env);
void compile_bf_instructions(elf_bf_env_t *e);
elfshobj_t *elfutils_read_elf_file(char *file);
void elfutils_save_elf_file(elfshobj_t *o, char *file);
elfshsect_t *insert_reloc_sec(elfshobj_t *f, eresi_Addr numrel, elfshsect_t *newsym);
elfshsect_t *insert_symtab_sec(elfshobj_t *f, eresi_Addr numsym, eresi_Addr strtab);
void fixup_dynamic_rela(elfshobj_t *f, eresi_Addr rel, eresi_Addr sz);
void fixup_dynamic_sym(elfshobj_t *f, eresi_Addr sym, eresi_Addr sz);
eresi_Addr set_next_reloc(elf_bf_link_map_t *l, Elf64_Word type, Elf64_Word sym, Elf64_Addr off, Elf64_Addr val);

#endif //ndef __ELF_BF_UTILS_H
