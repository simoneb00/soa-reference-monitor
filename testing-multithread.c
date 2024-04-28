#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define NUM_THREADS 10000
#define FILENAME "test.txt"
#define DIRNAME "test"
#define NEW_DIR "test/directory"

void *thread_function(void *arg) {
  /*  
    // write-open the file
    int fd = open(FILENAME, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        perror("Error in write-opening the file");
    } else {
        printf("File %s write-opened\n", FILENAME);
        close(fd);
    }

    // create hard link to file
    if (link(FILENAME, "hard_link.txt")) {
        perror("Error in hard link creation");
    } else {
        printf("Hard link to %s successfully created\n", FILENAME);
    }

    // create symlink to directory
    if (symlink(DIRNAME, "sym_link")) {
        perror("Error in symlink creation");
    } else {
        printf("Symbolic link to %s successfully created\n", DIRNAME);
    }

    // rename the file
    if (rename(FILENAME, "rename.txt")) {
        perror("Error in file renaming");
    } else {
        printf("File %s successfully renamed\n", FILENAME);
    }

    // unlink the file
    if (unlink(FILENAME)) {
        perror("Error in file deletion");
    } else {
        printf("File %s successfully deleted\n", FILENAME);
    }

    // unlink the directory
    if (unlink(DIRNAME)) {
        perror("Error in file deletion");
    } else {
        printf("File %s successfully deleted\n", DIRNAME);
    }

    // create symlink to directory
    if (symlink(FILENAME, "symlink.txt") == -1) {
        perror("Error in symbolic link creation");
    } else {
        printf("Symbolic link to %s successfully created\n", FILENAME);
    }
*/
    // create subdirectory in blacklisted directory
    if (creat(NEW_DIR, 0755) == -1) {
        perror("Error in directory creation");
    } else {
        printf("Directory %s created\n", NEW_DIR);
    }

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
