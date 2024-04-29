MAKE = make -C

all:
	$(MAKE) /lib/modules/$(shell uname -r)/build M=$(PWD)/syscall-table-discoverer modules
	$(MAKE) /lib/modules/$(shell uname -r)/build M=$(PWD)/reference-monitor modules
	$(MAKE) /lib/modules/$(shell uname -r)/build M=$(PWD)/file-system modules
	gcc -Wall -Wextra reference-monitor/user/user.c -o user
	gcc -Wall -Wextra file-system/singlefilemakefs.c -o file-system/singlefilemakefs

clean:
	$(MAKE) syscall-table-discoverer/ clean
	$(MAKE) reference-monitor/ clean
	$(MAKE) commands/ clean
	$(MAKE) file-system/ clean

mount: 
	$(MAKE) syscall-table-discoverer/ mount
	$(MAKE) reference-monitor/ mount
	$(MAKE) commands/ install
	$(MAKE) file-system/ mount-fs

unmount:
	rmmod the_usctm
	rmmod the_reference-monitor

testing:
	@chmod +x prepare_testing.sh
	@./prepare_testing.sh

	@gcc -Wall -Wextra testing-multithread.c -o testing-multithread

	@echo ""
	@echo ""
	@echo "Done, to run tests type ./testing.sh or ./testing-multithread"
