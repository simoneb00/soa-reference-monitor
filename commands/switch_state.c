#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>
#include <termios.h>

#include "commands.h"

int main(int argc, char *argv[]) {

    if (argc != 2 && argc != 3) {
        print_error("Usage: switch_state 0/1 or switch state 2/3 password");
        return 1;
    } else if (argc == 2 && atoi(argv[1]) >= 2) {
        print_error("Usage: switch_state state password");
        return 1;
    }

    long ret = syscall(WRITE_CODE, atoi(argv[1]), argv[2]);
    if (ret < 0) {
        switch (errno)
        {
            case EINVAL:
                print_error("State must be one of the following: 0 (OFF), 1 (ON), 2 (REC-OFF), 3 (REC-ON)");
                return 1;
            case EPERM:
                print_error("Access denied: only root (EUID 0) can change the state");
                return 1;
            case EACCES:
                print_error("Access denied: invalid password");
                return 1;
            default:
                perror("Error in switch_state");
                return 1;
        }
    }

    printf("State changed to %d\n", ret);
    
    return 0;
}
