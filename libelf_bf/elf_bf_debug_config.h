#ifndef _ELF_BF_DEBUF_CONFIG_H
#define _ELF_BF_DEBUF_CONFIG_H

#define FILENAMESZ 256
#define NUMINS 10

#include "symtab.h"
#include "elf_bf_utils.h"
typedef struct
{
  char type;
  eresi_Addr size;
} bf_int_t;


typedef struct {
  eresi_Addr dynrela;
  eresi_Addr dynsym;
  int numsym;
  int numrel;
  elf_bf_Sym *tape_ptr;
  elf_bf_Sym *tape_copy;

  eresi_Addr inssizes [NUMINS];
  eresi_Addr tape_len;
  char *exec;
  char *src;
} debug_config_t;
void elf_bf_write_debug(elf_bf_env_t *e, char *out);

#endif //def _ELF_BF_DEBUF_CONFIG_H
