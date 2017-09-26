#include <linux/module.h>          // included for all kernel modules
#include <linux/kernel.h>          // included for KERN_INFO
#include <linux/init.h>            // included for __init and __exit macros
#include <linux/kallsyms.h>        // included for kallsyms_lookup_name
#include <linux/netfilter.h>       // included for nf_hook_ops
#include <linux/netfilter_ipv4.h>  // included for NF_IP_PRI_FIRST
#include <linux/skbuff.h>          // included for struct sk_buff and related functions
#include <linux/ip.h>              // included for struct iphdr, ntohs, htons and others
#include <net/ip.h>                // included for ip_send_check
#include "asn-fwd-common.h"
#include "asn-fwd-ipip.h"
#include "asn-fwd-options.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Fabio Sabai");
MODULE_DESCRIPTION("Allows IP routing based on ASN");

module_param(table, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
MODULE_PARM_DESC(table, "Routing table where to lookup for ASN's");

module_param(format, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
MODULE_PARM_DESC(format, "Header format: 0 - IPIP, 1 - OPTIONS");

module_param(debug, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
MODULE_PARM_DESC(debug, "Enable/disable debug");

char format_name[2][8] = {"IPIP", "OPTIONS"};

unsigned int asnfwd_hook(const struct nf_hook_ops *ops,
                         struct sk_buff *skb,
                         const struct net_device *in,
                         const struct net_device *out,
                         int (*okfn)(struct sk_buff *))
{
	struct iphdr *iph;
	int ret = 0;

	/* sanity check */
	if (!skb)
		goto accept;

	/* recover the IPv4 header */
	iph = ip_hdr(skb);
	if (!iph)
		goto accept;

	PRINTK("Hook is %s\n", (in ? "pre-routing" : "local-out"));
	PRINTK("(Ogirinal) From %pI4 to %pI4.\n", &iph->saddr, &iph->daddr);

	switch (format)
	{
		case ASNFWD_FORMAT_IPIP:
			ret = asnfwd_hook_ipip(ops, skb, in, out, okfn);
			break;
		case ASNFWD_FORMAT_OPTIONS:
			ret = asnfwd_hook_options(ops, skb, in, out, okfn);
			break;
		default:
			// invalid option - should never reach
			return NF_ACCEPT;
	}

	/* packet changed */
	if (ret == ASNFWD_MODIFIED)
	{
		/* update iph pointer, may have changed above */
		iph = ip_hdr(skb);

		PRINTK("(Modified using %s) From %pI4 to %pI4.\n", format_name[format], &iph->saddr, &iph->daddr);

		/* no need to recalculate checksum for transport protocol,
		   but the new IP header needs a new checksum */
		skb->ip_summed = CHECKSUM_NONE;

		/* recalculate IP checksum */
		ip_send_check(iph);
	}
	/* packet is no good */
	else if (ret == ASNFWD_BAD)
	{
		return NF_DROP;
	}

accept:
	return NF_ACCEPT;
}

static struct nf_hook_ops ops_prerouting = {
	.hook	  = asnfwd_hook,
	.hooknum  = NF_INET_PRE_ROUTING,
	.pf	      = PF_INET,
	.priority = NF_IP_PRI_FIRST,
};

static struct nf_hook_ops ops_output = {
	.hook	  = asnfwd_hook,
	.hooknum  = NF_INET_LOCAL_OUT,
	.pf	      = PF_INET,
	.priority = NF_IP_PRI_FIRST,
};

static int __init init_main(void)
{
#ifdef CONFIG_IP_MULTIPLE_TABLES
	unsigned long sym_addr;

	if (format != ASNFWD_FORMAT_IPIP && format != ASNFWD_FORMAT_OPTIONS)
	{
		printk(KERN_ERR "[ASN-FWD] Invalid format: %d. Valid formats are %d (%s) and %d (%s)\n", format,
		                          ASNFWD_FORMAT_IPIP, format_name[ASNFWD_FORMAT_IPIP],
								  ASNFWD_FORMAT_OPTIONS, format_name[ASNFWD_FORMAT_OPTIONS]);
		return -EINVAL;
	}

	sym_addr = kallsyms_lookup_name("fib_get_table");
	if (sym_addr == 0)
	{
		printk(KERN_ERR "[ASN-FWD] fib_get_table not found");
		return -ENOSYS;
	}

	my_fib_get_table = (fib_get_table_t) sym_addr;

	nf_register_hook(&ops_prerouting); // always returns 0
	nf_register_hook(&ops_output); // always returns 0

	printk(KERN_INFO "[ASN-FWD] Netfilter hook added. table = %d, format = %s, debug is %s\n", table, format_name[format], (debug ? "on" : "off"));

	return 0;
#else
	/* we need multiple tables support */

	printk(KERN_ERR "[ASN-FWD] CONFIG_IP_MULTIPLE_TABLES not defined.\n");

	return -ENOPROTOOPT;
#endif /* CONFIG_IP_MULTIPLE_TABLES */
}

static void __exit cleanup_main(void)
{
	nf_unregister_hook(&ops_prerouting);
	nf_unregister_hook(&ops_output);

	printk(KERN_INFO "[ASN-FWD] Netfilter hook removed.\n");
}


module_init(init_main);
module_exit(cleanup_main);