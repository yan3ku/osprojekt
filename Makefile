obj-m += netclient.o netrelay.o
netclient-y += client.o aux.o
netrelay-y += relay.o aux.o

PWD := $(CURDIR)

all:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules


clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
