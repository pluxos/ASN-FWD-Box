#include "asn-fwd-ipip.h"
#include "asn-fwd-common.h"

/*
181		 if (unlikely(skb_headroom(skb) < hh_len && dev->header_ops)) {
182				 struct sk_buff *skb2;
183 
184				 skb2 = skb_realloc_headroom(skb, LL_RESERVED_SPACE(dev));
185				 if (skb2 == NULL) {
186						 kfree_skb(skb);
187						 return -ENOMEM;
188				 }
189				 if (skb->sk)
190						 skb_set_owner_w(skb2, skb->sk);
191				 consume_skb(skb);
192				 skb = skb2;
193		 }
*/

/**
 * asnfwd_add_header - add the outer ANSFWD IPv4 header
 * @skb: the socket buffer
 * @addr: the ASN destination address
 *
 * This function adds the outer IPv4 header with the destination address
 * set to the ASN looked at the ASNFWD_TABLE
 */
int asnfwd_add_header(struct sk_buff *skb, __be32 addr)
{
	struct iphdr *iph = ip_hdr(skb);
	struct iphdr *orig_iph;
	int err = 0;

	/* we need sizeof(struct iph) bytes at the start of the buffer */
	if (skb_headroom(skb) < sizeof(struct iphdr))
	{
		PRINTK("No space to add header. SKB headroom = %d\n", skb_headroom(skb));
		err = ENOMEM;
		goto end;
	}

	/* push data a few bytes right to make room for ASN-FWD header */
	skb_push(skb, sizeof(struct iphdr));

	/* it's necessary to reset the pointers, because the header pointer changed */
	skb_reset_network_header(skb);
	skb_set_transport_header(skb, sizeof(struct iphdr));

	/* clear the new space */
	memset((void *) ip_hdr(skb), 0, sizeof(struct iphdr));

	/* update iph pointer */
	iph = ip_hdr(skb);

	/* set orig_iph pointer */
	orig_iph = ipip_hdr(skb);

	/* fill the ASN-FWD option struct and copy it to the end of the IP header */
	iph->version = IPVERSION;
	iph->ihl = sizeof(struct iphdr) >> 2;
	iph->tos = orig_iph->tos;
	iph->tot_len = htons(ntohs(orig_iph->tot_len) + sizeof(struct iphdr));
	iph->id = orig_iph->id;
	iph->frag_off = orig_iph->frag_off;
	iph->ttl = orig_iph->ttl;
	iph->protocol = ASNFWD_PROTOCOL;
	iph->saddr = orig_iph->saddr;
	iph->daddr = addr;

	/* checksum will be recalculated in asnfwd_hook */

end:
	return err;
} 

/**
 * ansfwd_remove_header - remove the outer ASNFWD IPv4 header
 * @skb: the socket buffer
 *
 * This function removes the outer IPv4 header added previously by the ASN-FWD-Box
 */
void asnfwd_remove_header(struct sk_buff *skb)
{
	struct iphdr *iph = ip_hdr(skb);
	__u8 ttl = iph->ttl;

	/* not a ASNFWD packet */
	if (iph->protocol != ASNFWD_PROTOCOL)
		return;

	/* pull buffer data pointer to overwrite ASN-FWD header */
	skb_pull(skb, iph->ihl * 4);

	/* it's necessary to reset the pointer, because the header pointer changed */
	skb_reset_network_header(skb);

	/* update iph pointer */
	iph = ip_hdr(skb);

	/* copy outer TTL to inner IP header */
	iph->ttl = ttl;

	/* checksum will be recalculated in asnfwd_hook */
}

unsigned int asnfwd_hook_ipip(const struct nf_hook_ops *ops,
                              struct sk_buff *skb,
                              const struct net_device *in,
                              const struct net_device *out,
                              int (*okfn)(struct sk_buff *))
{
	struct iphdr *iph = ip_hdr(skb);
	__be32 addr = 0;

#if 0
	/* lets begin with ICMP packets, to have some flow control */
	if (iph->protocol != IPPROTO_ICMP && iph->protocol != ASNFWD_PROTOCOL)
		return ASNFWD_SKIPPED;
#endif // 0

	if (iph->protocol == ASNFWD_PROTOCOL)
	{
		PRINTK("Is ASNFWD protocol\n");

		asnfwd_remove_header(skb);
	}
	else
	{
		if ((addr = asnfwd_find_route(iph, in, out)) != 0)
		{
			PRINTK("Route found\n");

			if (asnfwd_add_header(skb, addr) != 0)
				return ASNFWD_BAD; /* something went wrong, better drop the packet */
		}
		/* no table found, no route found or incomplete route found */
	}

	/* packet changed in some way */
	if (iph->protocol == ASNFWD_PROTOCOL || addr)
	{
		/* update iph pointer, may have changed above */
		iph = ip_hdr(skb);

		PRINTK("(Modified) From %pI4 to %pI4.\n", &iph->saddr, &iph->daddr);

		/* no need to recalculate checksum for transport protocol,
		   but the new IP header needs a new checksum */
		skb->ip_summed = CHECKSUM_NONE;

		/* recalculate IP checksum */
		ip_send_check(iph);

		return ASNFWD_MODIFIED;
	}
	else
	{
		return ASNFWD_SKIPPED;
	}
}
