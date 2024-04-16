#include <stdio.h>
#include <fcntl.h>


int main(void){

    int ret = open("test.txt", O_WRONLY);
    if (ret < 0) {
        perror("There was an error in opening test.txt");
        return 1;
    }


    return 0;
}
