#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <string.h>

#define NUM_THREADS 30000
#define FILENAME "test.txt"
#define DIRNAME "test"
#define NEW_DIR "/home/sbauco/soa-reference-monitor/test/directory"

void *thread_function() {
    pid_t x = syscall(__NR_gettid);
  
    // write-open the file
    int fd = open(FILENAME, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        perror("Error in write-opening the file");
    } else {
        printf("[Thread %d] File %s write-opened\n", x, FILENAME);

        char *buffer = "test\n";
        ssize_t bytes_written = write(fd, buffer, strlen(buffer));
        if (bytes_written < 0) {
            perror("Error in writing to file");
        } else {
            printf("[Thread %d] %s successfully updated \n", x, FILENAME);
        }

        close(fd);
    }

    // create hard link to file
    if (link(FILENAME, "hard_link.txt")) {
        perror("Error in hard link creation");
    } else {
        printf("[Thread %d] Hard link to %s successfully created\n", x, FILENAME);
    }

    // create symlink to directory
    if (symlink(DIRNAME, "sym_link")) {
        perror("Error in symlink creation");
    } else {
        printf("[Thread %d] Symbolic link to %s successfully created\n", x, DIRNAME);
    }

    // rename the file
    if (rename(FILENAME, "rename.txt")) {
        perror("Error in file renaming");
    } else {
        printf("[Thread %d] File %s successfully renamed\n", x, FILENAME);
    }

    // unlink the file
    if (unlink(FILENAME)) {
        perror("Error in file deletion");
    } else {
        printf("[Thread %d] File %s successfully deleted\n", x, FILENAME);
    }

    // create symlink to directory
    if (symlink(DIRNAME, "symlink") == -1) {
        perror("Error in symbolic link creation");
    } else {
        printf("[Thread %d] Symbolic link to %s successfully created\n", x, DIRNAME);
    }

    // create subdirectory in blacklisted directory
    if (mkdir(NEW_DIR, 0700) == -1) {
        perror("Error in directory creation");
    } else {
        printf("[Thread %d] Directory %s created\n", x, NEW_DIR);
    }

    return NULL;

}

int main() {
    pthread_t threads[NUM_THREADS];
    int thread_args[NUM_THREADS];
    int i, result;

    for (i = 0; i < NUM_THREADS; i++) {
        thread_args[i] = i;
        result = pthread_create(&threads[i], NULL, thread_function, &thread_args[i]);
        if (result) {
            fprintf(stderr, "Error in creating thread %d\n", i);
            exit(EXIT_FAILURE);
        }
    }

    for (i = 0; i < NUM_THREADS; i++) {
        result = pthread_join(threads[i], NULL);
        if (result) {
            fprintf(stderr, "Errore in waiting thread %d\n", i);
            exit(EXIT_FAILURE);
        }
    }

    return 0;
}
