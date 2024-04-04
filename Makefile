MAKE = make -C

all:
	$(MAKE) /lib/modules/$(shell uname -r)/build M=$(PWD)/syscall-table-discoverer modules
	$(MAKE) /lib/modules/$(shell uname -r)/build M=$(PWD)/reference-monitor modules
	$(MAKE) /lib/modules/$(shell uname -r)/build M=$(PWD)/file-system modules
	gcc reference-monitor/user/user.c -o user

clean:
	$(MAKE) $(PWD)/syscall-table-discoverer clean
	$(MAKE) $(PWD)/reference-monitor clean
	$(MAKE) $(PWD)/file-system clean

mount: 
	$(MAKE) syscall-table-discoverer mount
	$(MAKE) reference-monitor mount
	$(MAKE) file-system mount-fs

unmount:
	rmmod the_usctm
	rmmod the_reference-monitor
	rmmod the_file-system