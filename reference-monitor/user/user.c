#include <stdio.h>
#include <fcntl.h>


int main(int argc, char** argv){

    int ret = open("test/test1/test1.txt", O_WRONLY);
    if (ret < 0) {
        perror("There was an error in opening test.txt");
        return 1;
    }


    return 0;
}
