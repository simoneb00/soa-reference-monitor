#define PROC_FILENAME "/proc/syscall_codes"
#define print_error(s) {printf("\033[1;31m%s\033[0m\n", s);} 

int get_syscall_code(const char *syscall_name);