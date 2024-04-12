#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "commands.h"

int get_syscall_code(const char *syscall_name) {
    FILE *fp;
    char line[256];
    char name[256];
    int code = -1;

    fp = fopen(PROC_FILENAME, "r");
    if (fp == NULL) {
        perror("Error in opening proc file");
        return -1;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        if (sscanf(line, "%[^:]: %d", name, &code) == 2) {
            char *trimmed_name = strtok(name, " ");
            if (strcmp(trimmed_name, syscall_name) == 0) {
                fclose(fp);
                return code;
            }
        }
    }

    fclose(fp);
    return -1;
}
