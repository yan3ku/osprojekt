Linux kernel module that abuses TCP header to create relay.

# About

The TCP specification leaves 40 bytes of option fields unused. By swaping the destination/source with tcp options we can achive relay. Additional encryption can be added for example using perfect hashing. As proof of concept rot13 is used.