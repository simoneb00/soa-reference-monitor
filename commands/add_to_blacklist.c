#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>

#include "commands.h"

int main(int argc, char *argv[]) {

    if (argc != 2) {
        printf("Usage: add_to_blacklist file\n");
        return 1;
    }

    long ret = syscall(ADD_TO_BLACKLIST, argv[1]);
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
    
    return 0;
}