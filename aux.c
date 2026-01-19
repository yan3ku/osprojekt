#include "aux.h"

void
check_ipv4(struct sk_buff *skb) {
  struct iphdr *iph;
  struct udphdr *udph;
  struct tcphdr *tcph;
  void *hptr;
  int hlen;
  __sum16 *checkf;

  /* if (skb_cloned(skb) || skb_is_nonlinear(skb)) { */
  /*   if (pskb_expand_head(skb, 0, 0, GFP_ATOMIC)) */
  /*     return; */
  /* } */

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
  default:
    return;
  }
  hlen = ntohs(iph->tot_len) - iph->ihl*4;
  *checkf = 0;
  *checkf = csum_tcpudp_magic(iph->saddr, iph->daddr, hlen, iph->protocol,
			      csum_partial(hptr, hlen, 0));
}

void
push_tcp_opt(struct sk_buff *skb, __u32 value) {
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

  /* set tcp options 255 to address */
  tcp_opt[0] = 255;
  tcp_opt[1] = 8;
  tcp_opt[2] = (value >> 24) & 0xFF;
  tcp_opt[3] = (value >> 16) & 0xFF;
  tcp_opt[4] = (value >> 8)  & 0xFF;
  tcp_opt[5] = value & 0xFF;
  tcp_opt[6] = 0;
  tcp_opt[7] = 0;    
}

__u32
read_tcp_opt(struct sk_buff *skb, char kind) {
  struct tcphdr *tcph = tcp_hdr(skb);  
  char *opt_ptr = (char*)tcph + 20;
  char *opt_end = (char*)tcph + tcp_hdrlen(skb);
  __u32 value = 0;
  char len;

  while (opt_ptr < opt_end) {
    switch (*opt_ptr) {
      case 0: return 0;
      case 1: opt_ptr++; continue;
    };
    
    if (*opt_ptr == kind) {
      value = value | (opt_ptr[5] << 0);
      value = value | (opt_ptr[4] << 8);
      value = value | (opt_ptr[3] << 16);
      value = value | (opt_ptr[2] << 24);
      return value;
    }
    len = opt_ptr[1];
    opt_ptr += len;
  }
  return 0;
}

void
log_packet(struct sk_buff *skb)
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


