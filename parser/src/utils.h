#define PARSE_ARG 0x00000001
#define DATA_ARG  0x00000010

long long read_args(char**);
void log_msg(char*);
void log_err(char*);
void exit_on_error(int, char*);
void usage (char*);
