#include "asn-fwd-common.h"

unsigned int table = 100;
unsigned int format = ASNFWD_FORMAT_IPIP;
unsigned int debug = 0;
fib_get_table_t my_fib_get_table;

/**
 * asnfwd_find_route - find an ASN-FWD route
 * @iph: IP header 
 * @in: The input device, if incoming packet
 * @out: The output device, if local outgoing packet
 *
 * This function looks for ASN FWD route in the table
 * specified during module loading. Returns the address
 * or 0 if a route is not found.
 */
__be32 asnfwd_find_route(struct iphdr *iph,
                         const struct net_device *in,
                         const struct net_device *out)
{
	struct net *net;
	struct fib_table *tb;
	struct flowi4 fl4;
	struct fib_result res;
	struct fib_nh *nh;
	__be32 addr = 0;

	/* sanity check */
	if (!in && !out)
		goto end;

	/* recover net from input or output net_device */
	net = dev_net(in ? in : out);
	if (!net)
		goto end;

	/* recover the asn-fwd table */
	tb = my_fib_get_table(net,  table);
	if (!tb)
		goto end; /* no asn-fwd table found */

	/* lookup for the destination address */
	fl4.flowi4_oif = 0;  /*                   */
	fl4.flowi4_iif = 0;  /*                   */
	fl4.flowi4_mark = 0; /* irrelevant fields */
	fl4.flowi4_tos = 0;  /*                   */
	fl4.saddr = 0;       /*                   */
	fl4.flowi4_scope = RT_SCOPE_UNIVERSE;
	fl4.daddr = iph->daddr;
	if (fib_table_lookup(tb, &fl4, &res, 0) != 0)
		goto end;

	if (!res.fi)
		goto end; /* incomplete route */

	/* route found, recover the asn and place it on the destination address */
	nh = &FIB_RES_NH(res);
	if (!nh->nh_gw)
		goto end; /* incomplete route */

	PRINTK("Found GW = %pI4\n", &nh->nh_gw);

	addr = nh->nh_gw;

end:
	return addr;
}
