obj-m += the_file-system.o
the_file-system-objs += file-system.o file.o dir.o


all:
	gcc singlefilemakefs.c -o singlefilemakefs
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules 

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	
mount-fs: mount create-fs
	if [ ! -d "/mnt/ref-monitor-fs" ]; then \
        mkdir "/mnt/ref-monitor-fs"; \
    else \
        echo "/mnt/ref-monitor-fs already exists."; \
    fi

	mount -o loop -t singlefilefs image /mnt/ref-monitor-fs

mount:
	insmod the_file-system.ko

create-fs:
	dd bs=4096 count=100 if=/dev/zero of=image
	./singlefilemakefs image