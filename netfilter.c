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
      pr_info("RELAY TO VPN\n");
    }    
    return NF_ACCEPT;
  }


  if (iph->saddr == RELAY_HOST) {
    if(iph && iph->protocol == IPPROTO_TCP) {
      struct iphdr * iph = ip_hdr(skb);	
      struct tcphdr *tcph = tcp_hdr(skb);
      pr_info("RECEIVED FROM VPN\n");
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
