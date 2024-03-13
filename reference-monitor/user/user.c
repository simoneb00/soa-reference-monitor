#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#define READ_CODE 134 
#define WRITE_CODE 156

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

	printf("Enter the password: ");
	fflush(stdout); 
	scanf("%s", &password);

	int ret = syscall(WRITE_CODE, new_state, password);
	printf("Syscall returned %d\n", ret);

	if (ret == -EPERM) {
		printf("Access denied: only root (EUID 0) can change the state\n");
	}
}

int main(int argc, char** argv){
       read_state();
	   write_state();
	   read_state();

	   return 0;
}

