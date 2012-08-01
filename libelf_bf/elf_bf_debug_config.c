#include <libelfsh.h>
#include <stdio.h>
#include "elf_bf_debug_config.h"
#include "elf_bf_ops.h"
#include "elf_bf_utils.h"
void get_ins_sizes(elf_bf_exec_t *ee, eresi_Addr *inssz);

typedef enum {i_start, i_inc, i_dec, i_next, i_prev, i_branch_start, i_branch_end, i_exit} elf_bf_instypes;
char elf_bf_insname [NUMINS] = {'I','+','-','>','<', '[', ']', 'X'};
void print_debug_config(debug_config_t *config, char *out) {
  FILE *f;
  int i;
  f = fopen(out, "w");
  if (NULL == f) {
    perror("failed to save debug config");
    return;
  }
  //fprintf(f, "self.dynrela = 0x%x\n", config->dynrela);
  //  fprintf(f, "self.dynsym = 0x%x\n", config->dynrela);
  fprintf(f, "self.numsym = %d\n", config->numsym);
  fprintf(f, "self.tape_ptr_addr = 0x%x\n", config->tape_ptr->addr);
  fprintf(f, "self.tape_copy_addr = 0x%x\n", config->tape_copy->addr);
  fprintf(f, "self.exec_path = '%s'\n", config->exec);
  fprintf(f, "self.bf_src_path = '%s'\n", config->src);
  fprintf(f, "self.tape_len = %d\n", config->tape_len);
  fprintf(f, "self.instructions={");
  for(i = 0; i < NUMINS; i++) {
    fprintf(f,"'%c':%d, ", elf_bf_insname[i], config->inssizes[i]);
  }
  fprintf(f, "}\n");
  fclose(f);

}

void elf_bf_write_debug(elf_bf_env_t *e, char *out)
{
  debug_config_t config;

  //config.dynrela = e->e_exec.ee_dt_rela;
  // config.dynsym = e->e_exec.ee_dt_sym;
  config.numsym = e->e_exec.ee_num_used_syms;
  config.numrel = e->e_exec.ee_lm.lm_next_reloc;
  config.tape_ptr = e->e_exec.ee_ptr_tape_ptr;
  config.tape_copy = e->e_exec.ee_tape_ptr;
  config.tape_len = e->e_exec.ee_tape_len;
  get_ins_sizes(&e->e_exec, config.inssizes);

  config.exec = e->e_exec.ee_lm.lm_out_name;
  config.src =  e->e_bf_sourcepath;
  print_debug_config(&config, out);
}

void get_ins_sizes(elf_bf_exec_t *ee, eresi_Addr *inssz)
{
  int was_allocated = ee->ee_lm.lm_allocated;
  eresi_Addr old_next = ee->ee_lm.lm_next_reloc;
  if (was_allocated) { //don't want it to allocate twice
    ee->ee_lm.lm_allocated = 0;
    ee->ee_lm.lm_next_reloc = 0;
  }
  inssz[i_start] = init_scatch_space(ee);
  inssz[i_inc] = elfops_increment(ee);
  inssz[i_dec] = elfops_decrement(ee);
  inssz[i_next] = elfops_increment_ptr(ee);
  inssz[i_prev] = elfops_decrement_ptr(ee);
  inssz[i_branch_start] = elfops_branch_start(ee);
  inssz[i_branch_end] = elfops_branch_end(ee);
  inssz[i_exit] = elfops_exit(ee);
  ee->ee_lm.lm_allocated = was_allocated;
  ee->ee_lm.lm_next_reloc = old_next;
}
