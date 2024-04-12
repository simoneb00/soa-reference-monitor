#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>

#include "commands.h"

int main(int argc, char *argv[]) {

    long ret;
    int code;

    if (argc != 2) {
        printf("Usage: add_to_blacklist file\n");
        return 1;
    }

    code = get_syscall_code("add_to_blacklist");
    if (code == -1) {
        printf("Cannot get code for add_to_blacklist\n");
        return 1;
    }

    ret = syscall(code, argv[1]);
    if (ret < 0) {
        switch(errno) {
            case EPERM:
                print_error("The reference monitor is not in a reconfiguration state");
                return 1;
            case ENOENT:
                print_error("No such file or directory");
                return 1;
            default:
                perror("Error in add_to_blacklist");
                return 1;
        }
    }

    printf("File successfully added to blacklist\n");
    
    return 0;
}