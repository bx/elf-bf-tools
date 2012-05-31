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
#include "elf_bf_ops.h"
#include "reloc.h"
#include "symtab.h"

eresi_Addr elfops_move_ptr(elf_bf_exec_t *e, eresi_Addr delta);
eresi_Addr elfops_add(elf_bf_exec_t *ee, eresi_Addr delta);
eresi_Addr elfops_unconditional_restart(elf_bf_exec_t *ee);
eresi_Addr elfops_prepare_branch(elf_bf_exec_t *ee);

eresi_Addr elfops_increment_ptr(elf_bf_exec_t *e)
{
  return elfops_move_ptr(e, 1);
}

eresi_Addr elfops_decrement_ptr(elf_bf_exec_t *e)
{
  return elfops_move_ptr(e, -1);
}

eresi_Addr elfops_move_ptr(elf_bf_exec_t *e, eresi_Addr delta)
{

  elf_bf_link_map_t *l = &(e->ee_lm);
  eresi_Addr start = l->lm_next_reloc;

  //change tape pointer
  set_next_reloc(l, R_X86_64_64, symtab_get_index(e->ee_ptr_tape_ptr),
                 symtab_get_value_addr(e->ee_ptr_tape_ptr), delta);
  //copy new tape value into workspace
  set_next_reloc(l, R_X86_64_COPY, symtab_get_index(e->ee_ptr_tape_ptr),
                 symtab_get_value_addr(e->ee_tape_ptr), 0);

   return l->lm_next_reloc - start;
 }

 eresi_Addr elfops_increment(elf_bf_exec_t *e)
 {
   return elfops_add(e, 1);
 }

 eresi_Addr elfops_decrement(elf_bf_exec_t *e)
 {
   return elfops_add(e,-1);
 }


 eresi_Addr elfops_add(elf_bf_exec_t *ee, eresi_Addr delta)
 {
   elf_bf_link_map_t *l = &(ee->ee_lm);

   eresi_Addr start = l->lm_next_reloc;

   //we assume that correct value is in scratch space, just do addition
   set_next_reloc(l, R_X86_64_64, symtab_get_index(ee->ee_tape_ptr),
                  symtab_get_value_addr(ee->ee_tape_ptr), delta);

   eresi_Addr setupi, copyi;
   elf_bf_Rela setup, copy;

   //update tape
   setupi = set_next_reloc(l, 0, 0, 0, 0);

   //copy new value back to tape
   copyi = set_next_reloc(l, R_X86_64_COPY, symtab_get_index(ee->ee_tape_copy),
                            0, 0);

   //go back at actually setup first entry
   reloc_get_reloc_entry(l, setupi, &setup);
   reloc_get_reloc_entry(l, copyi, &copy);
   //setup next entry so it knows where tape pointer is
   reloc_set_rela(&setup, R_X86_64_64, symtab_get_index(ee->ee_ptr_tape_ptr),
                  reloc_get_offset_addr(&copy), 0);
  return l->lm_next_reloc - start;
}

eresi_Addr elfops_branch_start(elf_bf_exec_t *ee)
{

  elf_bf_link_map_t *l = &(ee->ee_lm);
  eresi_Addr start = l->lm_next_reloc;

  elfops_prepare_branch(ee);


  eresi_Addr firsti;
  elf_bf_Rela first, next;

  //setup relocation entry that fixes dt_rela to jump past unconditional branch
  //we don't know address of next yet, so don't actually set it yet
  firsti = set_next_reloc(l, 0, 0, 0, 0);

  //setup relocation entry that fixes dt_relasz assuming unconditional branch
  set_next_reloc(l, R_X86_64_RELATIVE, 0, ee->ee_dt_relasz, ee->ee_dt_relasz_value - (l->lm_next_reloc*sizeof(Elf64_Rela)));

  //sets symbol's link addr to (value on tape)
  set_next_reloc(l, R_X86_64_COPY, symtab_get_index(ee->ee_tape_copy),
                 symtab_get_link_addr(ee->ee_lm.lm_ifunc), 0);

  //sets end to zero or ifunc, depending on link value of sym1 set earlier
  set_next_reloc(l, R_X86_64_64, symtab_get_index(ee->ee_lm.lm_ifunc),
                 ee->ee_reloc_end,0);

  //unconditional branch past ] (if tape is zero)
  //update dt_rela (addend to be filled in once ] is known)
  set_next_reloc(l, R_X86_64_RELATIVE, 0, ee->ee_dt_rela, 0);

  //update dt_relasz (addend to be filled in once ] is known)
  set_next_reloc(l, R_X86_64_RELATIVE, 0, ee->ee_dt_relasz, 0);

  //set end to zero to force immediate branch
  set_next_reloc(l, R_X86_64_RELATIVE, 0, ee->ee_reloc_end, 0);

  //fix first entry to it points to last entry
  reloc_get_reloc_entry(l, firsti, &first);
  reloc_get_reloc_entry(l, l->lm_next_reloc, &next);
  reloc_set_rela(&first, R_X86_64_RELATIVE, 0, ee->ee_dt_rela,
                 reloc_get_addr(&next));

  return l->lm_next_reloc - start;
}


eresi_Addr elfops_unconditional_restart(elf_bf_exec_t *ee)
{
  elf_bf_link_map_t *l = &(ee->ee_lm);
  eresi_Addr start = l->lm_next_reloc;


  elfops_prepare_branch(ee);

  set_next_reloc(l, R_X86_64_RELATIVE, 0, ee->ee_reloc_end, 0); //force branch

  return l->lm_next_reloc - start;
}

eresi_Addr init_scatch_space(elf_bf_exec_t *ee)
{
  elf_bf_link_map_t *l = &(ee->ee_lm);
  eresi_Addr start = l->lm_next_reloc;

  //copy new tape value into workspace
  set_next_reloc(l, R_X86_64_COPY, symtab_get_index(ee->ee_ptr_tape_ptr),
                 symtab_get_value_addr(ee->ee_tape_ptr), 0);
  return l->lm_next_reloc - start;
}
eresi_Addr elfops_branch_end(elf_bf_exec_t *ee)
{
  elf_bf_link_map_t *l = &(ee->ee_lm);
  eresi_Addr start = l->lm_next_reloc;

  //setup relocation entry that fixes dt_rela
  set_next_reloc(l, R_X86_64_RELATIVE, 0, ee->ee_dt_rela,0);

  //setup relocation entry that fixes dt_relasz
  set_next_reloc(l, R_X86_64_RELATIVE, 0, ee->ee_dt_relasz,0);

  elfops_prepare_branch(ee);

    //sets symbol's indx to (value on tape)
  //sets symbol's link addr to (value on tape)
  set_next_reloc(l, R_X86_64_COPY, symtab_get_index(ee->ee_tape_copy),
                 symtab_get_link_addr(ee->ee_lm.lm_ifunc), 0);

  //sets end to zero or ifunc, depending on link value of sym1 set earlier
  set_next_reloc(l, R_X86_64_64, symtab_get_index(ee->ee_lm.lm_ifunc),
                 ee->ee_reloc_end,0);

  //sets end to original value
  //symnum is ignored
  set_next_reloc(l, R_X86_64_RELATIVE, 0, ee->ee_reloc_end,
                 ee->ee_reloc_end_value);

  return l->lm_next_reloc - start;
}


eresi_Addr elfops_prepare_branch(elf_bf_exec_t *ee)
{
  elf_bf_link_map_t *l = &(ee->ee_lm);
  eresi_Addr start = l->lm_next_reloc;

  set_next_reloc(l, R_X86_64_RELATIVE, 0,
                 get_l_buckets(l->lm_l_s), 0); //let l_buckets to NULL
  // set l_direct_opencount to 0
  set_next_reloc(l, R_X86_64_RELATIVE, 0,
                  get_l_direct_opencount(l->lm_l_s), 0);
  set_next_reloc(l, R_X86_64_RELATIVE, 0, get_l_libname_next(l->lm_l_s), get_l_relocated(l->lm_l_s)-4*sizeof(int)); // rewire l_libname->next so relocated bit gets cleared
  set_next_reloc(l, R_X86_64_RELATIVE, 0, get_l_prev(l->lm_l_s), l->lm_l_s); // prev points to self so it gets processed again

    //set own relrosize as 0 so memory protections arent set
  set_next_reloc(l, R_X86_64_RELATIVE, 0,
                 get_l_relro_size(l->lm_l_s), 0);
  return l->lm_next_reloc - start;
}

eresi_Addr elfops_exit(elf_bf_exec_t *ee)
{
  eresi_Addr start;
  elf_bf_link_map_t *l = &(ee->ee_lm);
  start = l->lm_next_reloc;

  //this will end up causing the loader to divide by zero
  //if (l->lm_allocated) {
  //  reloc_set_rela(&r0, R_X86_64_TLSDESC, 0, 0, 0);
  //  l->lm_next_reloc = index;
  //}

  // force a branch to run original relocation entrires

  // restore PLT stuff
  set_next_reloc(l, R_X86_64_RELATIVE, 0, ee->ee_dt_jmprel, ee->ee_dt_jmprel_value);
  set_next_reloc(l, R_X86_64_RELATIVE, 0, ee->ee_dt_pltrelsz, ee->ee_dt_pltrelsz_value);

  elfops_prepare_branch(ee);


  //restore  RELA to point to entry after branch
  eresi_Addr relai, bucketi;
  elf_bf_Rela rela, bucket;

  //don't know all the information we need to set in this yet
  relai = set_next_reloc(l, 0, 0, 0, 0);

  //fix RELACOUNT accordingly
  // should probably calculate the 6
  set_next_reloc(l, R_X86_64_RELATIVE, 0, ee->ee_dt_relasz,
                 ee->ee_relasz_orig + 6*sizeof(Elf64_Rela));

  //force immediate branch so that we finally process PLT entries
  set_next_reloc(l, R_X86_64_RELATIVE, 0, ee->ee_reloc_end, 0);

  // restore l_buckets
  bucketi = set_next_reloc(l, R_X86_64_RELATIVE, 0, get_l_buckets(l->lm_l_s),
                 ee->ee_dt_gnu_hash);

  // now go back at steup relai
  reloc_get_reloc_entry(l, relai, &rela);
  reloc_get_reloc_entry(l, bucketi, &bucket);
  reloc_set_rela(&rela, R_X86_64_RELATIVE, 0, ee->ee_dt_rela,
                 reloc_get_addr(&bucket));

  //restore l->libname->next
  set_next_reloc(l, R_X86_64_RELATIVE, 0, get_l_libname_next(l->lm_l_s), 0);

  //restore l_direct_opencount
  set_next_reloc(l, R_X86_64_RELATIVE, 0, get_l_direct_opencount(l->lm_l_s), 1);

  //restore l_prev
  set_next_reloc(l, R_X86_64_RELATIVE, 0, get_l_prev(l->lm_l_s), 0);

  //restore symtable size to original value TODO
  //reloc_set_rela(&r, R_X86_64_RELATIVE, 0, 0, 0);

  //restore  RELA to point to original dynrel
  set_next_reloc(l, R_X86_64_RELATIVE, 0, ee->ee_dt_rela,ee->ee_rela_orig);

  //restore RELACOUNT or whatever to original value
  set_next_reloc(l, R_X86_64_RELATIVE, 0, ee->ee_dt_relasz, ee->ee_relasz_orig);

  return l->lm_next_reloc - start;
}
