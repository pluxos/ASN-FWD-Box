#ifndef _ASN_FWD_OPTIONS_H
#define _ASN_FWD_OPTIONS_H

#include <linux/skbuff.h>          // included for struct sk_buff and related functions
#include <linux/ip.h>              // included for struct iphdr, ntohs, htons and others
#include <net/ip.h>                // included for ip_send_check

#define IPOPT_ASNFWD_TYPE 222 /* 11011110 - copy:1 class:2 number:30 */
#define IPOPT_ASNFWD_LEN  sizeof(struct asnfwd_opt)

struct __attribute__((packed)) asnfwd_opt {
	unsigned char type;
	unsigned char len;
	__be32 addr;
	unsigned char pad1;
	unsigned char pad2;
};

int asnfwd_find_option(struct iphdr *iph, struct asnfwd_opt **opt);
void asnfwd_set_dst_from_option(struct sk_buff *skb, struct asnfwd_opt *opt);
int asnfwd_set_dst_from_table(struct sk_buff *skb, __be32 addr);
unsigned int asnfwd_hook_options(const struct nf_hook_ops *ops,
                                 struct sk_buff *skb,
                                 const struct net_device *in,
                                 const struct net_device *out,
                                 int (*okfn)(struct sk_buff *));

#endif /* _ASN_FWD_OPTIONS_H */
