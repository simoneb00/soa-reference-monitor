#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>
#include <string.h>

#include "commands.h"

int main(int argc, char *argv[]) {

    long ret;
    int code, mode;
    char *filename;

    if (argc != 3) {
        printf("Usage: remove_from_blacklist file mode\n");
        return 1;
    }

    mode = atoi(argv[2]);

    filename = (char *)malloc(strlen(argv[1] + 1));
    if (!filename) {
        printf("Error in malloc allocation\n");
        return 1;
    }
    strcpy(filename, argv[1]);

    code = get_syscall_code("remove_from_blacklist");
    if (code == -1) {
        printf("Cannot get code for remove_from_blacklist\n");
        return 1;
    }

    ret = syscall(code, filename, mode);
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

    printf("File successfully removed from blacklist\n");
    
    return 0;
}