#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "elf_funcs.h"
#include "utils.h"

static char*
get_phdr_perms_from_int(int perms) {
  switch(perms) {
    case 1:
      return "--X";
    case 2:
      return "-W-";
    case 3:
      return "-WX";
    case 4:
      return "R--";
    case 5:
      return "R-X";
    case 6:
      return "RW-";
    case 7:
      return "RWX";
    default:
      return "UNKOWN";
  }
}

static char*
get_program_header_from_int(int phdr) {
  switch(phdr) {
    case 0x01:
      return "EHDR_LOAD\0";
    case 0x02:
      return "EHDR_DYNAMIC\0";
    case 0x03:
      return "EHDR_INTERP\0";
    case 0x04:
      return "EHDR_NOTE\0";
    case 0x05:
      return "EHDR_NOTE";
    case 0x06:
      return "EHDR_PHDR\0";
    case 0x06474e550:
      return "EHDR_GNU_EH_FRAME\0";
    case 0x06474e551:
      return "EHDR_GNU_STACK\0";
    case 0x06474e552:
      return "EHDR_GNU_RELRO\0";
    case 0x06474e553:
      return "EHDR_GNU_PROPERTY\0";
    default:
      return "EHDR_UNKNOWN\0";
  }
}

void
parse_section_headers(unsigned char* elf_file, elf_bin_t* bin)
{
  log_msg("Parsing ELF section headers");
  unsigned short shnum = bin->hdr->e_shnum;
  bin->shdr = malloc(sizeof(Elf64_Shdr) * shnum);

  unsigned char* tmp_file = elf_file;
  tmp_file = tmp_file + bin->hdr->e_shoff;

  for (int i = 0; i < shnum; i++) {
    memcpy(bin->shdr + (sizeof(Elf64_Shdr) * 1), tmp_file, sizeof(Elf64_Shdr));
    tmp_file = tmp_file + sizeof(Elf64_Shdr);
  }
}

void* 
parse_program_headers(unsigned char* elf_file, elf_bin_t* bin) {
  log_msg("Parsing ELF program headers");
  unsigned short phnum = bin->hdr->e_phnum;
  bin->phdr = malloc(sizeof(Elf64_Phdr) * phnum);
  if (NULL == bin->phdr) {
    log_err("Failed to allocate space for program headers");

    return NULL;
  }

  unsigned char* tmp_file = elf_file;
  tmp_file = tmp_file + bin->hdr->e_phoff; // Get to program header offset

  for (int i = 0; i < phnum; i++) {
    memcpy(bin->phdr + (sizeof(Elf64_Phdr) * i), tmp_file, sizeof(Elf64_Phdr));
    tmp_file = tmp_file + sizeof(Elf64_Phdr);
  }
}

void
parse_header(unsigned char* elf_file, elf_bin_t* bin)
{
  log_msg("Parsing ELF header");
  bin->hdr = malloc(sizeof(Elf64_Ehdr));
  memcpy(bin->hdr, elf_file, EHDR_SIZE);
}

void
parse_sections(unsigned char* elf_file, elf_bin_t* bin)
{
  log_msg("Parsing ELF sections");
  return;
}

void
parse_elf(unsigned char* elf_file, elf_bin_t* bin)
{
  log_msg("Parsing ELF");
  parse_header(elf_file, bin);
  parse_program_headers(elf_file, bin);
  parse_section_headers(elf_file, bin);
  parse_sections(elf_file, bin);
}

void
print_elf_header(elf_bin_t* bin) {
  printf("Magic:\t");
  for (int i = 0; i < EI_NIDENT; i++) {
    printf("%.2x ", bin->hdr->e_ident[i]);
  }

  printf("\nElf header\n");
  printf("===========================\n");
  printf("Machine type:               %d\n", bin->hdr->e_machine);
  printf("Object file type:           %d\n", bin->hdr->e_type);
  printf("Object file version:        %d\n", bin->hdr->e_version);
  printf("Entry point:                0x%llx\n", bin->hdr->e_entry);
  printf("Program header offset:      0x%llx\n", bin->hdr->e_phoff);
  printf("Section header offset:      0x%llx\n", bin->hdr->e_shoff);
  printf("Processor flags:            %d\n", bin->hdr->e_flags);
  printf("Header size:                %d\n", bin->hdr->e_ehsize);
  printf("Program header size:        %d\n", bin->hdr->e_phentsize);
  printf("Program headers:            %d\n", bin->hdr->e_phnum);
  printf("Section header size:        %d\n", bin->hdr->e_shentsize);
  printf("Section headers:            %d\n", bin->hdr->e_shnum);
  printf("Section string table index: %d\n", bin->hdr->e_shstrndx);
  printf("===========================\n\n");
}

void
print_program_headers(elf_bin_t* bin) {
  Elf64_Phdr* tmp_phdr = bin->phdr;
  char* phdr_str = calloc(1, 1024);
  char* perms_str = calloc(1, 1024);

  printf("Elf program headers\n");
  printf("===========================\n");

  for (int i = 0; i < bin->hdr->e_phnum; i++) {
    phdr_str = get_program_header_from_int(tmp_phdr->p_type);
    perms_str = get_phdr_perms_from_int(tmp_phdr->p_flags);

    printf("Type:        %s        \n",   phdr_str);
    printf("Perms:       %s        \n",   perms_str);
    printf("Offset:      0x%llx    \n",   tmp_phdr->p_offset);
    printf("Vaddr:       0x%llx    \n",   tmp_phdr->p_vaddr);
    printf("Paddr:       0x%llx    \n",   tmp_phdr->p_paddr);
    printf("Filesz:      0x%llx    \n",   tmp_phdr->p_filesz);
    printf("Memsz:       0x%llx    \n",   tmp_phdr->p_memsz);
    printf("Align:       0x%llx    \n\n", tmp_phdr->p_align);

    tmp_phdr += sizeof(Elf64_Phdr);
    phdr_str = NULL;
    perms_str = NULL;
  }
  printf("===========================\n\n");
}

void
describe_elf(elf_bin_t* bin)
{
  print_elf_header(bin);
  print_program_headers(bin);

}

/*
  Parse the Elf Header
*/
// TODO: do the text formatting in a sane way
unsigned long long parse_elf_header(FILE *fp, Elf64_Ehdr *ehdr) {
  fread(ehdr->e_ident,      EI_NIDENT,                 1, fp);
  fread(&ehdr->e_type,      sizeof(ehdr->e_type),      1, fp);
  fread(&ehdr->e_machine,   sizeof(ehdr->e_machine),   1, fp);
  fread(&ehdr->e_version,   sizeof(ehdr->e_version),   1, fp);
  fread(&ehdr->e_entry,     sizeof(ehdr->e_entry),     1, fp);
  fread(&ehdr->e_phoff,     sizeof(ehdr->e_phoff),     1, fp);
  fread(&ehdr->e_shoff,     sizeof(ehdr->e_shoff),     1, fp);
  fread(&ehdr->e_flags,     sizeof(ehdr->e_flags),     1, fp);
  fread(&ehdr->e_ehsize,    sizeof(ehdr->e_ehsize),    1, fp);
  fread(&ehdr->e_phentsize, sizeof(ehdr->e_phentsize), 1, fp);
  fread(&ehdr->e_phnum,     sizeof(ehdr->e_phnum),     1, fp);
  fread(&ehdr->e_shentsize, sizeof(ehdr->e_shentsize), 1, fp);
  fread(&ehdr->e_shnum,     sizeof(ehdr->e_shnum),     1, fp);
  fread(&ehdr->e_shstrndx,  sizeof(ehdr->e_shstrndx),  1, fp);

  return ehdr->e_entry;
}

void parse_program_header(FILE *fp, Elf64_Phdr *phdr) {
  fread(&phdr->p_type,   sizeof(phdr->p_type),   1, fp);
  fread(&phdr->p_flags,  sizeof(phdr->p_flags),  1, fp);
  fread(&phdr->p_offset, sizeof(phdr->p_offset), 1, fp);
  fread(&phdr->p_vaddr,  sizeof(phdr->p_vaddr),  1, fp);
  fread(&phdr->p_paddr,  sizeof(phdr->p_paddr),  1, fp);
  fread(&phdr->p_filesz, sizeof(phdr->p_filesz), 1, fp);
  fread(&phdr->p_memsz,  sizeof(phdr->p_memsz),  1, fp);
  fread(&phdr->p_align,  sizeof(phdr->p_align),  1, fp);
}
