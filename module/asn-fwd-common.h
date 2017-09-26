#ifndef _ASN_FWD_COMMON_H
#define _ASN_FWD_COMMON_H

#include <linux/ip.h>              // included for struct iphdr, ntohs, htons and others
#include <net/ip_fib.h>            // included for fib_table_lookup and related structs
#include <net/ip.h>                // included for ip_send_check

#define PRINTK(...) do { if (debug) printk(KERN_INFO "[ASN-FWD] " __VA_ARGS__); } while (0)

#define ASNFWD_TABLE    100

#define ASNFWD_MODIFIED 1
#define ASNFWD_SKIPPED  2
#define ASNFWD_BAD      3

#define ASNFWD_FORMAT_IPIP    0
#define ASNFWD_FORMAT_OPTIONS 1

typedef struct fib_table *(*fib_get_table_t)(struct net *, u32);

extern unsigned int table;
extern unsigned int format;
extern unsigned int debug;
extern fib_get_table_t my_fib_get_table;

__be32 asnfwd_find_route(struct iphdr *iph,
                         const struct net_device *in,
                         const struct net_device *out);

#endif /* _ASN_FWD_COMMON_H */
