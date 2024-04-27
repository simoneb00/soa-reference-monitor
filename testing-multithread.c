#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define NUM_THREADS 100
#define FILENAME "test.txt"

void *thread_function(void *arg) {
    // Apertura del file in modalità scrittura
    int fd = open(FILENAME, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd == -1) {
        perror("Errore durante l'apertura del file per la scrittura");
    } else {
        printf("File %s aperto per la scrittura\n", FILENAME);
        close(fd);
    }

    // Creazione di un hard link
    if (link(FILENAME, "hard_link.txt") == -1) {
        perror("Errore durante la creazione di un hard link");
    } else {
        printf("Hard link creato con successo\n");
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
            fprintf(stderr, "Errore durante la creazione del thread %d\n", i);
            exit(EXIT_FAILURE);
        }
    }

    for (i = 0; i < NUM_THREADS; i++) {
        result = pthread_join(threads[i], NULL);
        if (result) {
            fprintf(stderr, "Errore durante l'attesa del thread %d\n", i);
            exit(EXIT_FAILURE);
        }
    }

    return 0;
}
