#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "commands.h"

int main() {

    size_t files_size;
    size_t dirs_size;
    long ret;
    char *files, *dirs;
    int get_blacklist_size, print_blacklist;

    get_blacklist_size = get_syscall_code("get_blacklist_size");
    if (get_blacklist_size == -1) {
        printf("Cannot get code for get_blacklist_size\n");
        return 1;
    }

    print_blacklist = get_syscall_code("print_blacklist");
    if (print_blacklist == -1) {
        printf("Cannot get code for print_blacklist\n");
        return 1;
    }

    ret = (size_t)syscall(get_blacklist_size, &files_size, &dirs_size);
    if (ret < 0) {
        perror("Error in get_blacklist_size");
        return 1;
    }

    files = malloc(files_size);
    dirs = malloc(dirs_size);

    ret = syscall(print_blacklist, files, dirs, files_size, dirs_size);
    if (ret < 0) {
        perror("Error in print_blacklist");
        return 1;
    }

    printf("Blacklisted files:\n%s", files);
    printf("Blacklisted directories:\n%s", dirs);

    free(files);
    free(dirs);
    
    return 0;
}
