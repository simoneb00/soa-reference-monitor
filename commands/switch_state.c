#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>
#include <termios.h>

#include "commands.h"

#define PASSWORD_SIZE 256

void get_password(char password[])
{
    static struct termios oldt, newt;
    int i = 0;
    int c;

    tcgetattr( STDIN_FILENO, &oldt);
    newt = oldt;

    newt.c_lflag &= ~(ECHO);          

    tcsetattr( STDIN_FILENO, TCSANOW, &newt);

    while ((c = getchar())!= '\n' && c != EOF && i < PASSWORD_SIZE){
        password[i++] = c;
    }
    password[i] = '\0';

    tcsetattr( STDIN_FILENO, TCSANOW, &oldt);

}

int main(int argc, char *argv[]) {

    long ret;
    int state, code;
    char password[PASSWORD_SIZE];

    if (argc != 2) {
        print_error("Usage: switch_state state");
        return 1;
    }

    state = atoi(argv[1]);

    if (state > 1) {
        printf("Enter reference monitor password: ");
        get_password(password);
        puts("");
    }

    code = get_syscall_code("switch_state");
    if (code == -1) {
        printf("Cannot get code for switch_state\n");
        return 1;
    }

    ret = syscall(code, atoi(argv[1]), password);
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
