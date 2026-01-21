#include "aux.h"

static struct nf_hook_ops *nf_tracer_ops = NULL;
static struct nf_hook_ops *nf_tracer_out_ops = NULL;

unsigned int
nf_tracer_handler(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
  if (!skb) return NF_ACCEPT;

  struct iphdr *iph = ip_hdr(skb);
  struct tcphdr *tcph;
      
  if (iph->daddr != CLIENT_HOST) {
    if(iph && iph->protocol == IPPROTO_TCP) {
      tcph = tcp_hdr(skb);  
      __u32 orig = iph->daddr;
      encrypt((unsigned char*)&orig, 4, (char)2137);
      iph->daddr = RELAY_HOST;
      push_tcp_opt(skb, orig);
      pr_info("RELAY\n");
      check_ipv4(skb);
      encrypt_skb_data(skb);
      log_packet(skb);
    }
    return NF_ACCEPT;
  }

  if (iph->saddr == RELAY_HOST) {
    if(iph && iph->protocol == IPPROTO_TCP) {
      pr_info("MANGLING SOURCE (PRE)\n");      
      tcph = tcp_hdr(skb);
      __u32 orig_addr = read_tcp_opt(skb, 255);
      encrypt((unsigned char*)&orig_addr, 4, (char)2137);
      iph->saddr = orig_addr;
      encrypt_skb_data(skb);      
      check_ipv4(skb);
      log_packet(skb);
      
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
