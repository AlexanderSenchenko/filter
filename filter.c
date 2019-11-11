#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/udp.h>

#define DEVICE_NAME "filter"

static unsigned int hook_func(void*, struct sk_buff*, const struct nf_hook_state*);

static struct nf_hook_ops in_nfho = {
	.hook		  = hook_func,
	.pf		    = NFPROTO_INET,
	.hooknum	= NF_INET_LOCAL_IN,
	.priority	= NF_IP_PRI_FIRST,
};

unsigned int hook_func(void *priv, struct sk_buff *skb,
			                 const struct nf_hook_state *state)
{
  // struct iphdr *ip_header;
  struct udphdr *udp_header;
  // int src_port
  int dest_port;

  // ip_header = (struct iphdr *) skb_network_header(skb);
  udp_header = (struct udphdr*) skb_transport_header(skb);

  // src_port = ntohs(udp_header->source);
  dest_port = ntohs(udp_header->dest);

  // printk(KERN_INFO "src IP addr: %pI4\n", &ip_header->saddr);
  // printk(KERN_INFO "dest IP addr: %pI4\n", &ip_header->daddr);
  // printk(KERN_INFO "src port: %d\n", src_port);
  // printk(KERN_INFO "dest port: %d\n", dest_port);

  if (dest_port == 9999) {
    printk(KERN_INFO "Dropped packet with port %d\n", dest_port);
    return NF_DROP;
  }

  return NF_ACCEPT;
}

int __init filter_init(void)
{
  printk(KERN_INFO "Trying to create /proc/%s:\n", DEVICE_NAME);

  nf_register_net_hook(&init_net, &in_nfho);

  return 0;
}

void __exit filter_exit(void)
{
  nf_unregister_net_hook(&init_net, &in_nfho);
  printk(KERN_INFO "/proc/%s removed\n", DEVICE_NAME);
}

module_init(filter_init);
module_exit(filter_exit);

MODULE_LICENSE("GPL");