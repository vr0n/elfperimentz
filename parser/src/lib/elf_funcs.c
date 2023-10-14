#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "elf_funcs.h"
#include "utils.h"

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

void 
parse_program_headers(unsigned char* elf_file, elf_bin_t* bin) {
  log_msg("Parsing ELF program headers");
  unsigned short phnum = bin->hdr->e_phnum;
  bin->phdr = malloc(sizeof(Elf64_Phdr) * phnum);

  unsigned char* tmp_file = elf_file;
  tmp_file = tmp_file+ bin->hdr->e_phoff;

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
describe_elf(elf_bin_t* bin)
{
  printf("ELF HEADER\n");
  printf("===========================\n");
  printf("MACHINE TYPE: %d\n", bin->hdr->e_machine);
  printf("OBJECT FILE TYPE: %d\n", bin->hdr->e_type);
  printf("OBJECT FILE VERSION: %d\n", bin->hdr->e_version);
  printf("ENTRY POINT: 0x%llx\n", bin->hdr->e_entry);
  printf("PROGRAM HEADER OFFSET: 0x%llx\n", bin->hdr->e_phoff);
  printf("SECTION HEADER OFFSET: 0x%llx\n", bin->hdr->e_shoff);
  printf("PROCESSOR FLAGS: %d\n", bin->hdr->e_flags);
  printf("HEADER SIZE: %d\n", bin->hdr->e_ehsize);
  printf("PROGRAM HEADER SIZE: %d\n", bin->hdr->e_phentsize);
  printf("PROGRAM HEADERS: %d\n", bin->hdr->e_phnum);
  printf("SECTION HEADER SIZE: %d\n", bin->hdr->e_shentsize);
  printf("SECTION HEADERS: %d\n", bin->hdr->e_shnum);
  printf("SECTION STRING TABLE INDEX: %d\n", bin->hdr->e_shstrndx);
}

char* map_phdr_types(unsigned int type) {
  char* phdr_type;

  switch(type) {
    case 1: phdr_type = "LOAD\t";
            break;
    case 2: phdr_type = "DYNAMIC\t";
            break;
    case 3: phdr_type = "INTERP\t";
            break;
    case 4: phdr_type = "NOTE\t";
            break;
    case 5: phdr_type = "NOTE\t";
            break;
    case 6: phdr_type = "PHDR\t";
            break;
    case 1685382480: phdr_type = "GNU_EH_FRAME";
            break;
    case 1685382481: phdr_type = "GNU_STACK";
            break;
    case 1685382482: phdr_type = "GNU_RELRO";
            break;
    case 1685382483: phdr_type = "GNU_PROPERTY";
            break;
    default: phdr_type = "UKNOWN\t";
  }

  return phdr_type;
}

char* map_perms(unsigned int perms) {
  char* phdr_perms;

  switch(perms) {
    case 1: phdr_perms = "--X";
            break;
    case 2: phdr_perms = "-W-";
            break;
    case 3: phdr_perms = "-WX";
            break;
    case 4: phdr_perms = "R--";
            break;
    case 5: phdr_perms = "R-X";
            break;
    case 6: phdr_perms = "RW-";
            break;
    case 7: phdr_perms = "RWX";
            break;
    default: phdr_perms = "UNKOWN";
  }

  return phdr_perms;
}

void print_elf_header(Elf64_Ehdr *ehdr) {
  printf("Magic:\t");
  for (int i = 0; i < EI_NIDENT; i++) {
    printf("%.2x ", ehdr->e_ident[i]);
  }

  printf("\nType:\t %u\t\t\t\t", ehdr->e_type);
  printf("Machine:\t%u\n", ehdr->e_machine);
  printf("Version: %u\t\t\t\t", (unsigned short)(ehdr->e_version));
  printf("Entry Address:\t0x%.08llx\n", ehdr->e_entry);
  printf("Program Header Offset:\t0x%llx\t", ehdr->e_phoff);
  printf("Section Header Offset:\t0x%llx\n", ehdr->e_shoff);
  printf("Flags:\t %u\t\t\t\t", (unsigned short)(ehdr->e_flags));
  printf("Elf Header Size:\t%u\n", (unsigned short)(ehdr->e_ehsize));
  printf("Program Header Size:\t%u\t\t", (unsigned short)(ehdr->e_phentsize));
  printf("Program Headers:\t%u\n", (unsigned short)(ehdr->e_phnum));
  printf("Section Header Size:\t%u\t\t", (unsigned short)(ehdr->e_shentsize));
  printf("Section Headers:\t%u\n", (unsigned short)(ehdr->e_shnum));
  printf("String Table Index:\t%u\n\n", (unsigned short)(ehdr->e_shstrndx));
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

void print_program_header(Elf64_Phdr *phdr) {
  printf("Type:\t%s\t",         map_phdr_types(phdr->p_type));
  printf("Perms:\t%s\t\t",      map_perms(phdr->p_flags));
  printf("Offset:\t0x%llx\t",  phdr->p_offset);
  printf("Vaddr:\t0x%llx\n",   phdr->p_vaddr);
  printf("Paddr:\t0x%llx\t",   phdr->p_paddr);
  printf("Filesz:\t0x%llx\t",  phdr->p_filesz);
  printf("Memsz:\t0x%llx\t",   phdr->p_memsz);
  printf("Align:\t0x%llx\n\n", phdr->p_align);
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
