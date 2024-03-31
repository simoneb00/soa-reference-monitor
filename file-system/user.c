#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#define FILENAME "mount/ref-monitor-log.txt"

int main() {
    char *data = "Questo è un messaggio di log.\n";
    int fd;

    fd = open(FILENAME, O_WRONLY, 0644);
    if (fd < 0) {
        perror("Errore nell'apertura del file");
        exit(EXIT_FAILURE);
    }

    if (write(fd, data, strlen(data)) < 0) {
        perror("Errore nella scrittura nel file");
        close(fd);
        exit(EXIT_FAILURE);
    }

    close(fd);

    printf("Messaggio di log scritto con successo in %s\n", FILENAME);

    return 0;
}
