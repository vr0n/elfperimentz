#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <getopt.h>
#include "lib/elf_funcs.h"
#include "lib/utils.h"

#define MAX_PATH 4096

//typedef struct elf_bin {
//  Elf64_Ehdr* hdr;
//  unsigned int phdr_num;
//  Elf64_Phdr* phdr;
//  unsigned int shdr_num;
//  Elf64_Shdr* shdr;
//  unsigned int sec_num;
//  Elf64_Sec* sec;
//  unsigned int seg_num;
//  Elf64_Seg* seg;
//  unsigned long size;
//  unsigned long perms;
//  char* perms_chr;
//} elf_bin_t;

//void
//parse_section_headers(unsigned char* elf_file, elf_bin_t* bin)
//{
//  unsigned short shnum = bin->hdr->e_shnum;
//  bin->shdr = malloc(sizeof(Elf64_Shdr) * shnum);
//
//  unsigned char* tmp_file = elf_file;
//  tmp_file = tmp_file + bin->hdr->e_shoff;
//
//  for (int i = 0; i < shnum; i++) {
//    memcpy(bin->shdr + (sizeof(Elf64_Shdr) * i), tmp_file, sizeof(Elf64_Shdr));
//    tmp_file = tmp_file + sizeof(Elf64_Shdr);
//  }
//}

//void
//parse_program_headers(unsigned char* elf_file, elf_bin_t* bin)
//{
//  unsigned short phnum = bin->hdr->e_phnum;
//  bin->phdr = malloc(sizeof(Elf64_Phdr) * phnum);
//
//  unsigned char* tmp_file = elf_file;
//  tmp_file = tmp_file + bin->hdr->e_phoff;
//
//  for (int i = 0; i < phnum; i++) {
//    memcpy(bin->phdr + (sizeof(Elf64_Phdr) * i), tmp_file, sizeof(Elf64_Phdr));
//    tmp_file = tmp_file + sizeof(Elf64_Phdr);
//  }
//}

//void
//parse_header(unsigned char* elf_file, elf_bin_t* bin)
//{
//  bin->hdr = malloc(sizeof(Elf64_Ehdr));
//  memcpy(bin->hdr, elf_file, EHDR_SIZE);
//}
//
//void
//parse_sections(unsigned char* elf_file, elf_bin_t* bin)
//{
//  return;
//}
//
//void
//parse_elf(unsigned char* elf_file, elf_bin_t* bin)
//{
//  parse_header(elf_file, bin);
//  parse_program_headers(elf_file, bin);
//  parse_section_headers(elf_file, bin);
//  parse_sections(elf_file, bin);
//}

// describe_elf prints all major portions of an ELF file.
// It should only be used for debugging purposes as it assumes
// all of the ELF struct has been populated.
//void
//describe_elf(elf_bin_t* bin)
//{
//  printf("ELF HEADER\n");
//  printf("===========================\n");
//  printf("MACHINE TYPE: %d\n", bin->hdr->e_machine);
//  printf("OBJECT FILE TYPE: %d\n", bin->hdr->e_type);
//  printf("OBJECT FILE VERSION: %d\n", bin->hdr->e_version);
//  printf("ENTRY POINT: 0x%llx\n", bin->hdr->e_entry);
//  printf("PROGRAM HEADER OFFSET: 0x%llx\n", bin->hdr->e_phoff);
//  printf("SECTION HEADER OFFSET: 0x%llx\n", bin->hdr->e_shoff);
//  printf("PROCESSOR FLAGS: %d\n", bin->hdr->e_flags);
//  printf("HEADER SIZE: %d\n", bin->hdr->e_ehsize);
//  printf("PROGRAM HEADER SIZE: %d\n", bin->hdr->e_phentsize);
//  printf("PROGRAM HEADERS: %d\n", bin->hdr->e_phnum);
//  printf("SECTION HEADER SIZE: %d\n", bin->hdr->e_shentsize);
//  printf("SECTION HEADERS: %d\n", bin->hdr->e_shnum);
//  printf("SECTION STRING TABLE INDEX: %d\n", bin->hdr->e_shstrndx);
//}

int
main(int argc, char *argv[])
{
  if (argc < 2) {
    usage(argv[0]); // Usage auto-exits with status 1
  }

  long* args = calloc(1, sizeof(long));
  char* elf_file_name;
  read_args(argv, args, elf_file_name);

  // Handle args that exit first
  if (*args & HELP_ARG) {
    help(argv[0]);
    return FUNC_PASS;
  }

  struct stat stats;
  if (stat(elf_file_name, &stats) == 0) {
    log_msg("Opened file. Parsing ELF...");
  } else {
    log_err("File not found.");
    return FUNC_FAIL;
  }

  if (!(stats.st_mode & S_IRWXU)) {
    printf("File must have read, write, and execute perms...\n");
    return FUNC_FAIL;
  }

  FILE *fp;
  fp = fopen(elf_file_name, "r+b");
  if (fp == NULL) {
    char *fp_err = strcpy("Could not open file: %s\n", elf_file_name);
    exit_on_error(errno, fp_err);
  }

  unsigned char *elf_file = malloc(stats.st_size);
  fread(elf_file, stats.st_size, 1, fp);
  elf_bin_t* bin = malloc(sizeof(elf_bin_t));

  parse_elf(elf_file, bin);
  describe_elf(bin);
  log_msg("Closing target and exiting...\n");
  fclose(fp);
  return FUNC_PASS;
}