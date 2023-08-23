#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

// Helper functions for the project

/*
  Simple colorful logging functions
*/
void log_msg(char *log) {
  fprintf(stdout, "\033[0;34m[+] %s\n\033[0m", log);
}

void log_err(char *log) {
  fprintf(stderr, "\033[0;31m[+] %s\n\033[0m", log);
  exit(1); 
}

void exit_on_error(int err_no, char *err) {
  fprintf(stderr, "\033[0;31m[-] %s -- errno: %d\n", err, err_no);
  exit(1); 
}

/*
  Usage function
*/
void usage(char *program) {
  fprintf(stderr, "Usage: %s [OPTION]... [BINARY]\n\n", program);
  exit(1);
}

/*
  Function to check the permissions of the target binary.
  We must be able to read, write, and execute, or nothing else matters.
*/
int check_modes(struct stat stats) {
  // TODO: Figure out why write only works when the file is globally writeable
  mode_t mode = stats.st_mode;
  if (!S_ISREG(mode)) {
    fprintf(stderr, "\033[0;31m[-] Not a regular file!\n");
    exit(1);
  }

  if (!S_IRWXU & mode) {
    fprintf(stderr, "\033[0;31m[-] We don't have RWX!\n");
    exit(1);
  }

  return 0;
}
