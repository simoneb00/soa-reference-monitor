#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <termios.h>
#include <fcntl.h>
#include <errno.h>

#define READ_CODE 134 
#define WRITE_CODE 156
#define ADD_TO_BLACKLIST 174
#define RM_FROM_BLACKLIST 177
#define PRINT_BLACKLIST 178
#define ADD_TO_BLACKLIST 174
#define RM_FROM_BLACKLIST 177
#define PRINT_BLACKLIST 178

#define print_error(s) {printf("\033[1;31m%s\033[0m\n", s);} 

void read_state() {
    int ret = syscall(READ_CODE);
    printf("Syscall returned %d\n", ret);
}

void write_state() {
    int new_state;
    char password[256];


    printf("Enter the new state: ");
    fflush(stdout); 
    scanf("%d", &new_state);

    if (new_state > 1) {
        struct termios term;
        tcflag_t old_flags;
        
        // Disabilita l'echo dell'input
        tcgetattr(STDIN_FILENO, &term);
        old_flags = term.c_lflag;
        term.c_lflag &= ~(ECHO);
        tcsetattr(STDIN_FILENO, TCSANOW, &term);

        printf("Enter the password: ");
        fflush(stdout); 
        scanf("%s", password);

        // Ripristina i vecchi flag di termios
        term.c_lflag = old_flags;
        tcsetattr(STDIN_FILENO, TCSANOW, &term);

        printf("\n");
    }

    int ret = syscall(WRITE_CODE, new_state, password);
    printf("Syscall returned %d\n", ret);

    if (ret == -EPERM) {
        printf("Access denied: only root (EUID 0) can change the state\n");
    }
}

void print_blacklist(void) {
    int ret = syscall(PRINT_BLACKLIST);
    printf("Syscall print_blacklist returned %d\n", ret);
}

void add_to_blacklist(char *path) {
    int ret = syscall(ADD_TO_BLACKLIST, path);
    if (ret != 0) {
        switch (errno)
        {
        case ENOMEM:
            print_error("Error in adding file to blacklist");
            break;
        
        case ENOENT:
            print_error("File not found. Either the file does not exist or you're not in the directory containing the file.");
            break;
        }
    }
}

void remove_from_blacklist(char *path) {
    int ret = syscall(RM_FROM_BLACKLIST, path);
    printf("Syscall remove_from_blacklist returned %d\n", ret);
}

int main(int argc, char** argv){

    write_state();
    add_to_blacklist("test.txt");
    add_to_blacklist("test/test.txt");
    add_to_blacklist("prova");
    print_blacklist();

/*
    int ret = open("test.txt", O_RDWR);
    if (ret < 0) {
        perror("Open error: ");
        return 1;
    }

    printf("Open returned %d\n", ret);
    */


    return 0;
}
