#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>

#include "commands.h"

int main(int argc, char *argv[]) {

    if (argc != 3) {
        printf("Usage: remove_from_blacklist file mode\n");
        return 1;
    }

    long ret = syscall(RM_FROM_BLACKLIST, argv[1], atoi(argv[2]));
    if (ret < 0) {
        switch(errno) {
            case EINVAL:
                print_error("Mode must be 0 (DELETE_DIRS_ONLY) or 1 (DELETE_ALL)");
                return 1;
            case ENOENT:
                print_error("No such file or directory");
                return 1;
            default:
                perror("Error in add_to_blacklist");
                return 1;
        }
    }
    
    return 0;
}