#include "asn-fwd-options.h"
#include "asn-fwd-common.h"

static int ip_opt_len(const struct iphdr *iph)
{
	return (iph->ihl * 4) - sizeof(struct iphdr);
}

static void asnfwd_replace_eol(struct iphdr *iph)
{
	unsigned char *optptr = (unsigned char *) &(iph[1]);
	int optlen = ip_opt_len(iph);
	int len;

	for ( ; optlen > 0; )
	{
		switch (*optptr)
		{
		case IPOPT_END:
			*optptr = IPOPT_NOOP;
			PRINTK("Replaced IPOPT_END\n");
			/* pass through */
		case IPOPT_NOOP:
			optlen--;
			optptr++;
			continue;
		}

		/* already validated in asnfwd_find_option */
		len = optptr[1];
		optlen -= len;
		optptr += len;
	}
}

/**
 * asnfwd_find_option - find the ASN FWD option in IP header
 * @iph: IP header 
 * @opt: pointer to ASN FWD option, if found, NULL otherwise
 *
 * This function looks for ASN FWD option the IP header. If found,
 * set the @opt parameter to the start of the option. Returns true
 * if everything is ok (true not means an option was found, just
 * that no errors occurred). In case an ASN FWD option is found and
 * is not ok, i.e., incorrect lenght, etc, returns a non-zero value.
 */
int asnfwd_find_option(struct iphdr *iph, struct asnfwd_opt **opt)
{
	unsigned char *optptr;
	int optlen;
	int len;
	int err = 0;

	*opt = NULL;

	if (iph->ihl > 5)
	{
		optlen = ip_opt_len(iph);
		optptr = (unsigned char *) &(iph[1]);
		for ( ; optlen > 0; )
		{
			switch (*optptr)
			{
			case IPOPT_NOOP:
			case IPOPT_END:
				optlen--;
				optptr++;
				continue;
			}

			if (unlikely(optlen < 2))
				goto end; /* invalid option, has no length */

			len = optptr[1];
			if (len < 2 || len > optlen)
				goto end; /* invalid option, invalid length */	

			if (*optptr == IPOPT_ASNFWD_TYPE)
			{
				*opt = (struct asnfwd_opt *) optptr;
				if ((*opt)->len < IPOPT_ASNFWD_LEN)
					err = -EPROTO;

				goto end;
			}
			else
			{
				optlen -= len;
				optptr += len;
			}
		}
	}

end:
	return err;
}

/**
 * asnfwd_save_dst_to_option - save the original destination address in the options field 
 * @skb: the socket buffer 
 *
 * This function saves the original destination address in the IP packet options field,
 * using the ASN-FWD option type and class.
 */
static int asnfwd_save_dst_to_options(struct sk_buff *skb)
{
	struct iphdr *iph = ip_hdr(skb);
	struct asnfwd_opt opt;
	int err = 0;

	/* we need IPOPT_ASNFWD_LEN bytes at the start of the buffer
           and we need space in the IP header */
	if (skb_headroom(skb) < IPOPT_ASNFWD_LEN || MAX_IPOPTLEN - ip_opt_len(iph) < IPOPT_ASNFWD_LEN)
	{
		PRINTK("No space to add option. SKB headroom = %d, options length = %d\n",
				skb_headroom(skb), ip_opt_len(iph));
		err = ENOMEM;
		goto end;
	}

	/* replace any IPOPT_END that may appear before ASN-FWD option */
	asnfwd_replace_eol(iph);

	/* push IP header to make room for ASN-FWD option */
	skb_push(skb, IPOPT_ASNFWD_LEN);

	/* it's necessary to reset the pointer, because the header pointer changed */
	skb_reset_network_header(skb);

	/* move IP header to its new location 
	   ip_hdr(skb) -> new location
       iph -> old location */
	memmove((void *) ip_hdr(skb), (void *) iph, iph->ihl * 4);

	/* update iph pointer */
	iph = ip_hdr(skb);

	/* fill the ASN-FWD option struct and copy it to the end of the IP header */
	opt.type = IPOPT_ASNFWD_TYPE;
	opt.len = IPOPT_ASNFWD_LEN;
	opt.addr = iph->daddr;
	opt.pad1 = IPOPT_NOOP;
	opt.pad2 = IPOPT_END;

	memcpy((void *) iph + (iph->ihl * 4), (void *) &opt, sizeof(opt));

	/* update ihl and tot_len fields */
	iph->ihl = iph->ihl + (IPOPT_ASNFWD_LEN >> 2);
	iph->tot_len = htons(ntohs(iph->tot_len) + IPOPT_ASNFWD_LEN);

	/* checksum will be recalculated in asnfwd_hook */

end:
	return err;
}

/**
 * asnfwd_remove_option - remove ASN-FWD option from IP header
 * @skb: the socket buffer 
 * @opt: pointer to ASN-FWD option in IP header
 *
 * This function removes the ASN_FWD option from the IP header
 */
static void asnfwd_remove_option(struct sk_buff *skb, struct asnfwd_opt *opt)
{
	struct iphdr *iph = ip_hdr(skb);

	/* pull IP header to overwrite ASN-FWD option */
	skb_pull(skb, IPOPT_ASNFWD_LEN);

	/* it's necessary to reset the pointer, because the header pointer changed */
	skb_reset_network_header(skb);

	/* move IP header to its new location 
	   ip_hdr(skb) -> new location
       iph -> old location 
	   opt - iph -> number of IP header bytes before ASN-FWD options */
	memmove((void *) ip_hdr(skb), (void *) iph, (void *) opt - (void *) iph);

	/* update iph pointer */
	iph = ip_hdr(skb);

	/* update ihl and tot_len fields */
	iph->ihl = iph->ihl - (IPOPT_ASNFWD_LEN >> 2);
	iph->tot_len = htons(ntohs(iph->tot_len) - IPOPT_ASNFWD_LEN);

	/* checksum will be recalculated in asnfwd_hook */
}

/**
 * asnfwd_set_dst_from_table - set the destination field based on the routing table
 * @skb: the socket buffer 
 * @in: device where packet came from
 *
 * This function executes a lookup in the ASN-FWD table and, if an entry
 * is found, replaces the destionation field of the IP packet by the one
 * found in the table. The original destination address is saved as an
 * option in the IP packet.
 */
int asnfwd_set_dst_from_table(struct sk_buff *skb, __be32 addr)
{
	struct iphdr *iph = ip_hdr(skb);
	int err = 0;

	/* save destination address to IPv4 options */
	err = asnfwd_save_dst_to_options(skb);
    if (err != 0)
		goto end;

	/* update iph pointer, may have changed above */
	iph = ip_hdr(skb);

	/* replace destionation address */
	iph->daddr = addr;

	/* checksum will be recalculated in asnfwd_hook */

end:
	return err;
}

/**
 * asnfwd_set_dst_from_option - set the destination field based on ASN-FWD option 
 * @skb: the socket buffer 
 * @opt: pointer to ASN-FWD option in IP header
 *
 * This function replaces the destination address by the one set in ASN-FWD option
 * and removes the ASN-FWD option from the IP header. @opt will be no more valid
 * after this function executes
 */
void asnfwd_set_dst_from_option(struct sk_buff *skb, struct asnfwd_opt *opt)
{
	struct iphdr *iph = ip_hdr(skb);

	/* set new destionation address */
	iph->daddr = opt->addr;

	/* remove ASN-FWD option */
	asnfwd_remove_option(skb, opt);

	/* opt is no more valid */
	
	/* checksum will be recalculated in asnfwd_hook */
}

unsigned int asnfwd_hook_options(const struct nf_hook_ops *ops,
                                 struct sk_buff *skb,
                                 const struct net_device *in,
                                 const struct net_device *out,
                                 int (*okfn)(struct sk_buff *))
{
	struct iphdr *iph = ip_hdr(skb);
	__be32 addr = 0;
	struct asnfwd_opt *opt;

#if 0
	/* lets begin with ICMP packets, to have some flow control */
	if (iph->protocol != IPPROTO_ICMP)
		return ASNFWD_SKIPPED;
#endif // 0

	if (asnfwd_find_option(iph, &opt) != 0)
		return ASNFWD_BAD; /* has option, but is invalid. Packet is not useful */

	if (opt)
	{
		PRINTK("Option found\n");

		asnfwd_set_dst_from_option(skb, opt);
	}
	else
	{
		if ((addr = asnfwd_find_route(iph, in, out)) != 0)
		{
			PRINTK("Route found\n");

			if (asnfwd_set_dst_from_table(skb, addr) != 0)
				return ASNFWD_BAD; /* something went wrong, better drop the packet */
		}
		/* no table found, no route found or incomplete route found */
	}
	
	/* packet changed in some way */
	if (opt || addr)
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
