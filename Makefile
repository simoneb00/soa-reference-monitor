all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD)/syscall-table-discoverer modules
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD)/reference-monitor modules
	gcc reference-monitor/user/user.c

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD)/syscall-table-discoverer clean
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD)/reference-monitor clean

mount: 
	insmod syscall-table-discoverer/the_usctm.ko
	insmod reference-monitor/the_reference-monitor.ko the_syscall_table=$$(cat /sys/module/the_usctm/parameters/sys_call_table_address) password="ref_monitor_password"

unmount:
	rmmod the_usctm
	rmmod the_reference-monitor
	