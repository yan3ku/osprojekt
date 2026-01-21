#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/string.h>
#include <linux/byteorder/generic.h>

#define QUAD4(a, b, c, d)						\
  htonl((((__u32)a) << 24) | (((__u32)b) << 16) | (((__u32)c) << 8) | ((__u32)d))

#define RELAY_HOST QUAD4(10, 10, 10, 5)
#define CLIENT_HOST QUAD4(10, 10, 10, 10)

void check_ipv4(struct sk_buff *skb);
void push_tcp_opt(struct sk_buff *skb, __u32 value);
__u32 read_tcp_opt(struct sk_buff *skb, char kind);
void log_packet(struct sk_buff *skb);
void encrypt_skb_data(struct sk_buff *skb);
void encrypt(unsigned char *data, int len, unsigned char key);



