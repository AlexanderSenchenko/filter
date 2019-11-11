FILE_NAME := filter

obj-m += $(FILE_NAME).o


.PHONY: check clean test_read test_ioctl reload create_dev

all:
	make -C /usr/src/linux-headers-$(shell uname -r) M=$(PWD) modules
	~/sign_module.sh $(FILE_NAME).ko

check:
	lsmod | grep $(FILE_NAME)

test_read:
	gcc test_read.c -o test_read

test_ioctl:
	gcc test_ioctl.c -o test_ioctl

reload:
	rmmod $(FILE_NAME)
	insmod $(FILE_NAME).ko

clean:
	make -C /usr/src/linux-headers-$(shell uname -r) M=$(PWD) clean