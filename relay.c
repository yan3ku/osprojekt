#include "aux.h"

static struct nf_hook_ops *nf_tracer_ops = NULL;
static struct nf_hook_ops *nf_tracer_post_ops = NULL;


static unsigned int
nf_tracer_post_handler(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
  struct iphdr *iph = ip_hdr(skb);

  if (iph->saddr == CLIENT_HOST) {
    if(iph && iph->protocol == IPPROTO_TCP) {
      iph->saddr = CLIENT_HOST;
      log_packet(skb);
      check_ipv4(skb);      
    }
    return NF_ACCEPT;    
  }
  
  return NF_ACCEPT;
}

static unsigned int
nf_tracer_handler(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
  if (!skb) return NF_ACCEPT;

  struct iphdr *iph = ip_hdr(skb);
  struct tcphdr *tcph;

  if (iph->saddr == CLIENT_HOST) {
    if(iph && iph->protocol == IPPROTO_TCP) {
      pr_info("RELAY TO DESTINATION\n");
      tcph = tcp_hdr(skb);
      __u32 orig_addr = read_tcp_opt(skb, 255);
      iph->daddr = orig_addr;
      check_ipv4(skb);
    }
    return NF_ACCEPT;    
  }

  /* not source CLIENT_HOST so relay to CLIENT_HOST */
  if (iph->daddr == CLIENT_HOST) {
    if(iph && iph->protocol == IPPROTO_TCP) {
      pr_info("RELAY TO CLIENT\n");
      tcph = tcp_hdr(skb);
      push_tcp_opt(skb, iph->saddr);
      iph = ip_hdr(skb);
      iph->daddr = CLIENT_HOST;
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

  nf_tracer_post_ops = (struct nf_hook_ops*)kcalloc(1,  sizeof(struct nf_hook_ops), GFP_KERNEL);  

  if(nf_tracer_ops!=NULL) {
    nf_tracer_post_ops->hook = (nf_hookfn*)nf_tracer_post_handler;
    nf_tracer_post_ops->hooknum = NF_INET_POST_ROUTING;
    nf_tracer_post_ops->pf = NFPROTO_IPV4;
    nf_tracer_post_ops->priority = NF_IP_PRI_FIRST;

    nf_register_net_hook(&init_net, nf_tracer_post_ops);
  }  

  return 0;
}

static void __exit nf_tracer_exit(void) {
  if(nf_tracer_ops != NULL) {
    nf_unregister_net_hook(&init_net, nf_tracer_ops);
    kfree(nf_tracer_ops);
  }

  if(nf_tracer_post_ops != NULL) {
    nf_unregister_net_hook(&init_net, nf_tracer_post_ops);
    kfree(nf_tracer_post_ops);
  }
}

module_init(nf_tracer_init);
module_exit(nf_tracer_exit);

MODULE_LICENSE("GPL");
