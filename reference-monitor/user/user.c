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
    printf("Syscall add_to_blacklist returned %d\n", ret);
}

void remove_from_blacklist(char *path) {
    int ret = syscall(RM_FROM_BLACKLIST, path);
    printf("Syscall remove_from_blacklist returned %d\n", ret);
}

int main(int argc, char** argv){

    write_state();
/*    print_blacklist();*/
    add_to_blacklist("test.txt");/*
    add_to_blacklist("/test.txt");
    print_blacklist();
    remove_from_blacklist("/test.txt");
    print_blacklist(); */

    int ret = open("test.txt", O_RDWR);
    if (ret == -1) {
        perror("Error in opening file");
        return 1;
    }

    printf("File aperto con successo con i seguenti flag: %d\n", O_RDWR);
    close(ret);

    return 0;
    return 0;
}
