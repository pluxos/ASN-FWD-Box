KDIR=/lib/modules/$(shell uname -r)/build
#KDIR=/usr/src/linux-source-3.13.0/linux-source-3.13.0

obj-m += asn-fwd.o

asn-fwd-objs := asn-fwd-main.o asn-fwd-common.o asn-fwd-ipip.o asn-fwd-options.o

all:
		@$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
		@$(MAKE) -C $(KDIR) M=$(PWD) clean
