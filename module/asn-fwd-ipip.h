#ifndef _ASN_FWD_IPIP_H
#define _ASN_FWD_IPIP_H

#include <linux/skbuff.h>          // included for struct sk_buff and related functions
#include <linux/ip.h>              // included for struct iphdr, ntohs, htons and others
#include <net/ip.h>                // included for ip_send_check

#define ASNFWD_PROTOCOL 254 // experimental

int asnfwd_add_header(struct sk_buff *skb, __be32 addr);
void asnfwd_remove_header(struct sk_buff *skb);
unsigned int asnfwd_hook_ipip(const struct nf_hook_ops *ops,
                              struct sk_buff *skb,
                              const struct net_device *in,
                              const struct net_device *out,
                              int (*okfn)(struct sk_buff *));

#endif /* _ASN_FWD_IPIP_H */
