obj-m += cross_page_attack.o

KDIR := /home/veritas/linux-5.13
# KDIR := /lib/modules/`uname -r`/build

PWD := $(shell pwd)

.PHONY: default

default:
	make -C $(KDIR) M=$(PWD) modules

clean:
	rm -rf *.o .* .cmd *.ko *.mod.c .tmp_versions
