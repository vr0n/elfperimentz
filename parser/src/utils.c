#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>

long long read_args(char** argv) {

  int offset = 1; // Skip arg 0, which is just the program name

  while (NULL != argv[offset]) {
    parse_arg(argv[offset]);
    offset++;
  }
}

/*
 * Simple colorful logging functions
 */
void
log_msg(char *log)
{
  fprintf(stdout, "\n\033[0;34m[+] %s\n\033[0m\n", log);
}

void
log_err(char *log)
{
  fprintf(stderr, "\n\033[0;31m[+] %s\n\033[0m\n", log);
  exit(1); 
}

void
exit_on_error(int err_no, char *err)
{
  fprintf(stderr, "\033[0;31m[-] %s -- errno: %d\n", err, err_no);
  exit(1); 
}

void
usage(char* program)
{
  fprintf(stderr, "Usage: %s [ OPTIONS ] [ TARGET ]\n\n", program);
  fprintf(stderr, "Use %s -h to see the help menu\n", program);
  exit(1);
}
