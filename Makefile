KERNEL_PATH ?= /lib/modules/$(shell uname -r)/build

obj-m += teabox.o
teabox-objs := ./src/teabox.o ./src/ftrace_hook.o ./src/seccomp_filters.o

all:
	make -C $(KERNEL_PATH) M=$(PWD) modules

clean:
	make -C $(KERNEL_PATH) M=$(PWD) clean
