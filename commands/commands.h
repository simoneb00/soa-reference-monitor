#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,0,0)
#define READ_CODE 134 
#define WRITE_CODE 156
#define ADD_TO_BLACKLIST 174
#define RM_FROM_BLACKLIST 177
#define PRINT_BLACKLIST 178
#define GET_BLACKLIST_SIZE 180
#else 
#define READ_CODE 134 
#define WRITE_CODE 174
#define ADD_TO_BLACKLIST 177
#define RM_FROM_BLACKLIST 178
#define PRINT_BLACKLIST 180
#define GET_BLACKLIST_SIZE 181
#endif

#define print_error(s) {printf("\033[1;31m%s\033[0m\n", s);} 