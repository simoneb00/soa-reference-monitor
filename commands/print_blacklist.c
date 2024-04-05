#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "commands.h"

int main() {

    size_t files_size;
    size_t dirs_size;

    long ret = (size_t)syscall(GET_BLACKLIST_SIZE, &files_size, &dirs_size);
    if (ret < 0) {
        perror("Error in get_blacklist_size");
        return 1;
    }

    char *files = malloc(files_size);
    char *dirs = malloc(dirs_size);

    ret = syscall(PRINT_BLACKLIST, files, dirs, files_size, dirs_size);
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
