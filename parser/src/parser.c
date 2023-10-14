#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include "lib/elf_funcs.h"
#include "lib/utils.h"

int
main(int argc, char *argv[])
{
  if (argc < 2) {
    usage(argv[0]); // Usage auto-exits with status 1
  }

  long* args = calloc(1, sizeof(long));
  read_args(argv, args);

  // Handle args that self-exit first
  if (*args & HELP_ARG) {
    help(argv[0]);
    return FUNC_PASS;
  }

  // Then everything else
  char* elf_file_name = argv[argc - 1]; // We don't need this before now
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

  if (*args & PARSE_ARG) {
    parse_elf(elf_file, bin);
    describe_elf(bin);
  }
 
  log_msg("Closing target and exiting...\n");
  fclose(fp);

  return FUNC_PASS;
}
