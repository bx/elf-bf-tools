#include <libelfsh.h>

eresi_Addr get_dynent_addr(elfshobj_t *f, u_int t)
{
  // lookup where dynamic table section gets loaded
  elfshsect_t *dyn_sec;
  dyn_sec = elfsh_get_section_by_name(f, ".dynamic", NULL, NULL, NULL);
  Elf64_Dyn *dyntab = dyn_sec->data;
  eresi_Addr dynsz = dyn_sec->shdr->sh_size/sizeof(Elf64_Dyn);
  eresi_Addr i;

  for (i = 0; (i < dynsz) && (DT_NULL != dyntab[i].d_tag); i++) {
    //printf("address of tag %d: %lx\n", dyntab[i].d_tag, dyn_sec->shdr->sh_addr + (i * sizeof(Elf64_Dyn)) + sizeof(dyntab[i].d_tag));
    if (dyntab[i].d_tag == t){
      //printf("address of %d: %lx\n", t, dyn_sec->shdr->sh_addr + (i * sizeof(Elf64_Dyn)) + sizeof(dyntab[i].d_tag));
      return dyn_sec->shdr->sh_addr + (i * sizeof(Elf64_Dyn)) + 8; //return address of this value
    }
  }

  return NULL;
}
