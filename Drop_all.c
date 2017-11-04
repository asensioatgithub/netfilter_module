#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

static struct nf_hook_ops nfho;

unsigned int hook_func(unsigned int hooknum,struct sk_buff *skb,const struct net_device *in,const struct net_device *out,int(okfn)(struct sk_buff *)){
	return NF_DROP;

}

int init_module(){
	nfho.hook = hook_func;
	nfho.hooknum = NF_INET_PRE_ROUTING;
	nfho.pf = PF_INET;
	nfho.priority = NF_IP_PRI_FIRST; 

	nf_register_hook(&nfho);
	return 0;

}

void cleanup_module(void){
	nf_unregister_hook(&nfho);
}