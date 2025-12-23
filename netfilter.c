#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/string.h>
#include <linux/byteorder/generic.h>

#define QUAD4(a, b, c, d) \
  htonl((((__u32)a) << 24) | (((__u32)b) << 16) | (((__u32)c) << 8) | ((__u32)d))

#define RELAY_HOST QUAD4(10, 10, 10, 5)
#define LOCAL_HOST  QUAD4(10, 10, 10, 10)

static struct nf_hook_ops *nf_tracer_ops = NULL;
static struct nf_hook_ops *nf_tracer_out_ops = NULL;

static void check_ipv4(struct sk_buff *skb);

void check_ipv4(struct sk_buff *skb) {
  struct iphdr *iph;
  struct udphdr *udph;
  struct tcphdr *tcph;
  void *hptr;
  int hlen;
  __sum16 *checkf;

  if (skb_is_nonlinear(skb))
    skb_linearize(skb);

  iph = ip_hdr(skb);
#ifdef HW_OFFLOAD		/* no idea how to make this work.... */
  skb->ip_summed = CHECKSUM_PARTIAL;
  skb->csum_start = (unsigned char*)iph - skb->data;
  skb->csum_offset = (unsigned char *)&(iph->check) - (unsigned char *)iph;
#else
  skb->ip_summed = CHECKSUM_NONE;
  skb->csum_valid = 0;
  iph->check = 0; 			/* spec requires the checksum is calculated with check = 0 */
  iph->check = ip_fast_csum((u8 *)iph, iph->ihl);
#endif
  
  switch (iph->protocol) {
  case IPPROTO_TCP:
    hptr = tcph = tcp_hdr(skb);
    checkf = &(tcph->check);
    break;
  case IPPROTO_UDP:
    hptr = udph = udp_hdr(skb);
    checkf = &(udph->check);
    break;
  }
  hlen = ntohs(iph->tot_len) - iph->ihl*4;
  *checkf = 0;
  *checkf = csum_tcpudp_magic(iph->saddr, iph->daddr, hlen, iph->protocol,
			      csum_partial(hptr, hlen, 0));
}

static void push_tcp_opt(struct sk_buff *skb) {
  if (skb_is_nonlinear(skb))
    skb_linearize(skb);
  
  struct tcphdr *tcph = tcp_hdr(skb);
  struct iphdr *iph = ip_hdr(skb);
  int iplen = iph->ihl*4;
  
  char *beg = skb_push(skb, 8);
  memmove(beg, beg+8, iplen + tcp_hdrlen(skb)); /* move up */
  /* update the tcp_hdr ip_hdr location */
  skb_reset_network_header(skb);
  skb_set_transport_header(skb, iplen);
  /* reassign headers */
  iph =  ip_hdr(skb);
  tcph = tcp_hdr(skb);
  /* get tcp opt ptr */
  unsigned char *tcp_opt = (unsigned char*)tcph + tcp_hdrlen(skb);
  /* update length */
  be16_add_cpu(&iph->tot_len, 8);
  tcph->doff += 2;

  /* set tcp opt */
  memset(tcp_opt, 0, 8);

  /* set tcp options 255 to 1 */
  tcp_opt[0] = 255;
  tcp_opt[1] = 8;
  tcp_opt[1] = 0x01;  
}


static void log_packet(struct sk_buff *skb)
{

    struct iphdr * iph = ip_hdr(skb);	
    struct tcphdr *tcph = tcp_hdr(skb);  
    pr_info("source : %pI4:%hu | dest : %pI4:%hu | type: %d\n",
	    &(iph->saddr),
	    ntohs(tcph->source),
	    &(iph->daddr),
	    ntohs(tcph->dest),
	    skb->pkt_type);
}


static unsigned int
nf_tracer_handler(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
  if (!skb) return NF_ACCEPT;
  log_packet(skb);


  struct iphdr *iph = ip_hdr(skb);
  if (iph->daddr != LOCAL_HOST) {
    struct iphdr * iph = ip_hdr(skb);	
    iph->daddr = RELAY_HOST;
    if(iph && iph->protocol == IPPROTO_TCP) {
      struct tcphdr *tcph = tcp_hdr(skb);
      push_tcp_opt(skb);
      pr_info("RELAY\n");
    }
    /* check_ipv4(skb); */
    return NF_ACCEPT;
  }


  if (iph->saddr == RELAY_HOST) {
    if(iph && iph->protocol == IPPROTO_TCP) {
      struct iphdr * iph = ip_hdr(skb);	
      struct tcphdr *tcph = tcp_hdr(skb);
      pr_info("RECEIVED FROM RELAY\n");
    }
    return NF_ACCEPT;    
  }

  return NF_ACCEPT;
}




static int __init nf_tracer_init(void) {

  nf_tracer_ops = (struct nf_hook_ops*)kcalloc(1,  sizeof(struct nf_hook_ops), GFP_KERNEL);

  if(nf_tracer_ops!=NULL) {
    nf_tracer_ops->hook = (nf_hookfn*)nf_tracer_handler;
    nf_tracer_ops->hooknum = NF_INET_PRE_ROUTING;
    nf_tracer_ops->pf = NFPROTO_IPV4;
    nf_tracer_ops->priority = NF_IP_PRI_FIRST;

    nf_register_net_hook(&init_net, nf_tracer_ops);
  }

  nf_tracer_out_ops = (struct nf_hook_ops*)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);

  if(nf_tracer_out_ops!=NULL) {
    nf_tracer_out_ops->hook = (nf_hookfn*)nf_tracer_handler;
    nf_tracer_out_ops->hooknum = NF_INET_LOCAL_OUT;
    nf_tracer_out_ops->pf = NFPROTO_IPV4;
    nf_tracer_out_ops->priority = NF_IP_PRI_FIRST;

    nf_register_net_hook(&init_net, nf_tracer_out_ops);
  }

  return 0;
}

static void __exit nf_tracer_exit(void) {

  if(nf_tracer_ops != NULL) {
    nf_unregister_net_hook(&init_net, nf_tracer_ops);
    kfree(nf_tracer_ops);
  }

  if(nf_tracer_out_ops != NULL) {
    nf_unregister_net_hook(&init_net, nf_tracer_out_ops);
    kfree(nf_tracer_out_ops);
  }
}

module_init(nf_tracer_init);
module_exit(nf_tracer_exit);

MODULE_LICENSE("GPL");
