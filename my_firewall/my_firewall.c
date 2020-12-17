#include <linux/init.h>
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/version.h>

#include <asm/uaccess.h>
#include <asm/unistd.h>
#include <linux/in.h>
#include <linux/kmod.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <linux/workqueue.h>
#include <net/sock.h>

#include <linux/icmp.h>
#include <linux/inet.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include <linux/netlink.h>
#include <linux/sched.h>
#include <linux/types.h>

//#include <arpa/inet.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("xsc");

static struct nf_hook_ops nfho_in;
static struct nf_hook_ops nfho_out;

// 七元组
struct filter_rule {
  unsigned int src_ip;
  unsigned int src_port;
  unsigned int dst_ip;
  unsigned int dst_port;
  unsigned int src_mask;
  unsigned int dst_mask;
  unsigned int protocol;
  unsigned int action;
  unsigned int record;
};
static struct filter_rule test;
static struct filter_rule rules[100];
static int rule_num;

struct state_ {
  unsigned int src_ip;
  unsigned short src_port;
  unsigned int dst_ip;
  unsigned short dst_port;
  unsigned short protocol;
};
static struct state_ *state_tables = NULL;
static char *parg = "220.181.111.147";
module_param(
    parg, charp,
    S_IRUGO); //用户态向内核态传参https://blog.csdn.net/zhudaozhuan/article/details/52214438

/// there is not a inet_addr in kernel. use in_aton  .
// https://www.cnblogs.com/52fhy/p/5007456.html
unsigned short calchash(unsigned int srcip, unsigned int dstip,
                        unsigned int srcport, unsigned int dstport,
                        unsigned int protocol) {
  unsigned int temp = srcip ^ dstip ^ srcport ^ dstport ^ protocol;
  unsigned char *p = (unsigned char *)&temp;
  return p[0] * 33 + p[1] * 33 + p[2] * 33 + p[3] * 33;
}
int hashcheck(unsigned short hash, unsigned int srcip, unsigned int dstip,
              unsigned int srcport, unsigned int dstport,
              unsigned int protocol) {
  return 0;
  int i;
  for (i = 0; i < 5; ++i) {
    if (state_tables[(i + hash) & 0xff].src_ip =
            srcip && state_tables[(i + hash) & 0xff].src_port == srcport &&
            state_tables[(i + hash) & 0xff].dst_ip == dstip &&
            state_tables[(i + hash) & 0xff].dst_port == dstport &&
            state_tables[(i + hash) & 0xff].protocol == protocol) {
      return 1;
    }
  }
  return 0;
}
unsigned int ip_compare(unsigned int rule, unsigned int mask,
                        unsigned int cur) {
  //根据规则中的零判断网段
  //网络字节序和正常手写是反着的
  //所以最后的0会在最前面
  unsigned int a = 1;
  return rule == (((a << mask) - 1) & cur);
  if ((rule & 0xffffffff) == 0) {
    return 1;
  } else if ((rule & 0xffffff00) == 0) {
    return rule == (cur & 0x000000ff);
  } else if ((rule & 0xffff0000) == 0) {
    return rule == (cur & 0x0000ffff);
  } else if ((rule & 0xff000000) == 0) {
    return rule == (cur & 0x00ffffff);
  } else {
    return rule == cur;
  }
  return 0;
}
unsigned int hook_func(void *priv, struct sk_buff *skb,
                       const struct nf_hook_state *state) {
  if (!skb)
    return NF_ACCEPT;
  struct iphdr *ip = NULL;
  struct tcphdr *tcp = NULL;
  struct udphdr *udp = NULL;
  struct icmphdr *icmp = NULL;
  unsigned int src_ip, dst_ip, src_port, dst_port, protocol;
  src_ip = dst_ip = src_port = dst_port = protocol = 0;

  ip = ip_hdr(skb); // ip头结构指针
  src_ip = ntohl(ip->saddr);
  dst_ip = ntohl(ip->daddr);
  printk("ip_protocol:%d, ip_saddr:%pI4, ip_dassr:%pI4\n", ip->protocol,
         &ip->saddr, &ip->daddr);
  switch (ip->protocol) {
  case IPPROTO_TCP:
    tcp = tcp_hdr(skb);
    src_port = ntohs(tcp->source);
    dst_port = ntohs(tcp->dest);
    protocol = IPPROTO_TCP;
    break;
  case IPPROTO_UDP:
    udp = udp_hdr(skb);
    src_port = ntohs(udp->source);
    dst_port = ntohs(udp->dest);
    protocol = IPPROTO_UDP;
    break;
  case IPPROTO_ICMP:
    icmp = icmp_hdr(skb);
    protocol = IPPROTO_ICMP;
    break;
  default:
    break;
  }
  // printk("test %d %d %d\n",ip->saddr,src_ip,test.src_ip);
  //查状态检测表进行检测
  // src_ip, dst_ip, src_port, dst_port, protocol
  unsigned short hash_ = calchash(src_ip, dst_ip, src_port, dst_port, protocol);
  int ret = hashcheck(hash_, src_ip, dst_ip, src_port, dst_port, protocol);
  if (ret == 1) {
    return NF_ACCEPT;
  }
  printk("src_port:%d, dst_port:%d\n", src_port, dst_port);
  //规则匹配
  switch (ip->protocol) {
  case IPPROTO_TCP:
    // struct tcphdr *tcp; //显而易见，尽管ip和tcp不同层级，但应当有同样的结构
    //是否为SYN
    // if (tcp->syn == TCP_FLAG_SYN) {
    //匹配规则
    // test
    // for
    {
      int i;
      for (i = 0; i < rule_num; ++i) {
        if (rules[i].protocol == IPPROTO_TCP &&
            ip_compare(rules[i].src_ip, rules[i].src_mask, ip->saddr) &&
            ip_compare(rules[i].dst_ip, rules[i].dst_mask, ip->daddr) &&
            (rules[i].src_port == src_port || rules[i].src_port == 0) &&
            (rules[i].dst_port == dst_port || rules[i].dst_port == 0)) {
          if (rules[i].action) {
            printk("TCP SYN tcp_src_port:%d, tcp_dst_port:%d\n", src_port,
                   dst_port);
            return NF_ACCEPT; //不能忘记return
          } else {
            printk("TCP DROP tcp_src_port:%d, tcp_dst_port:%d\n", src_port,
                   dst_port);
            return NF_DROP;
          }
        } else {
          printk("TCP NO AC tcp_src_port:%d, tcp_dst_port:%d\n", src_port,
                 dst_port);
          return NF_ACCEPT;
        }
      }
      //如果0个规则，则需要默认回复通过
      return NF_ACCEPT;
    }
    break;
  case IPPROTO_UDP:
    //先查表
    // UDP不需要查看是否为SYN包
    //匹配规则
    // test
    // for循环
    {
      int i;
      for (i = 0; i < rule_num; ++i) {
        if (rules[i].protocol == IPPROTO_UDP &&
            ip_compare(rules[i].src_ip, rules[i].src_mask, ip->saddr) &&
            ip_compare(rules[i].dst_ip, rules[i].dst_mask, ip->daddr) &&
            (rules[i].src_port == src_port || rules[i].src_port == 0) &&
            (rules[i].dst_port == dst_port || rules[i].dst_port == 0)) {
          if (rules[i].action) {
            printk("UDP AC udp_src_port:%d, udp_dst_port:%d\n", src_port,
                   dst_port);
            return NF_ACCEPT; //不能忘记return
          } else {
            printk("UDP NO AC udp_src_port:%d, udp_dst_port:%d\n", src_port,
                   dst_port);
            return NF_DROP;
          }
        } else {
          printk("ip_saddr:%pI4, ip_dassr:%pI4 UDP DROP STATE udp_src_port:%d, "
                 "udp_dst_port:%d\n",
                 &ip->saddr, &ip->daddr, src_port, dst_port);
          return NF_ACCEPT;
        }
      }
      return NF_ACCEPT;
    }
    break;
  case IPPROTO_ICMP:
    //
    {
      int i;
      for (i = 0; i < rule_num; ++i) {
        if (rules[i].protocol == IPPROTO_UDP &&
            ip_compare(rules[i].src_ip, rules[i].src_mask, ip->saddr) &&
            ip_compare(rules[i].dst_ip, rules[i].dst_mask, ip->daddr) &&
            (rules[i].src_port == src_port || rules[i].src_port == 0) &&
            (rules[i].dst_port == dst_port || rules[i].dst_port == 0)) {
          if (rules[i].action) {
            printk("UDP AC udp_src_port:%d, udp_dst_port:%d\n", src_port,
                   dst_port);
            return NF_ACCEPT; //不能忘记return
          } else {
            printk("UDP NO AC udp_src_port:%d, udp_dst_port:%d\n", src_port,
                   dst_port);
            return NF_DROP;
          }
        } else {
          printk("ip_saddr:%pI4, ip_dassr:%pI4 UDP DROP STATE udp_src_port:%d, "
                 "udp_dst_port:%d\n",
                 &ip->saddr, &ip->daddr, src_port, dst_port);
          return NF_ACCEPT;
        }
      }
      return NF_ACCEPT;
    }
    printk("ip_protocol:%d, ip_saddr:%pI4, ip_dassr:%pI4 ICMP TYPE %u\n",
           ip->protocol, &ip->saddr, &ip->daddr, icmp->type);
    printk("ICMP TYPE %u\n", icmp->type);
    return NF_ACCEPT;
    break;
  default:
    printk("OTHER PROTOCOL\n");
    return NF_ACCEPT; //拒绝其他协议//默认通过
    break;
  }
}

// for netlink
#define NETLINK_TEST 17
static struct sock *nlsk = NULL;

int nltest_ksend(char *info, int len, int pid) {
  char *reply = NULL;
  int rlen;
  struct sk_buff *skb;
  struct nlmsghdr *nlh;
  int retval;

  // sprintf(reply, "NLTEST Relpay for '%s'", info);
  // rlen = strlen(reply) + 1;
  // rlen = rlen % 257;

  reply = info;
  // new
  rlen = len;

  skb = nlmsg_new(rlen, GFP_ATOMIC);
  if (skb == NULL) {
    printk("alloc reply nlmsg skb failed!\n");
    return -1;
  }

  nlh = nlmsg_put(skb, 0, 0, 0, NLMSG_SPACE(rlen) - NLMSG_HDRLEN, 0);
  memcpy(NLMSG_DATA(nlh), reply, rlen);
  printk("[kernel space] nlmsglen = %d\n", nlh->nlmsg_len);

  // NETLINK_CB(skb).pid = 0;
  NETLINK_CB(skb).dst_group = 0;

  printk("[kernel space] skb->data send to user: '%s'\n",
         (char *)NLMSG_DATA(nlh));

  retval = netlink_unicast(nlsk, skb, pid, MSG_DONTWAIT);
  printk("[kernel space] netlink_unicast return: %d\n", retval);
  return 0;
}

void nltest_krecv(struct sk_buff *skb) {
  struct nlmsghdr *nlh = NULL;
  char *data = NULL;
  char *end = "end";
  int pid;
  nlh = nlmsg_hdr(skb);
  if ((nlh->nlmsg_len < NLMSG_HDRLEN) || (skb->len < nlh->nlmsg_len)) {
    printk("Illegal netlink packet!\n");
    return;
  }
  data = (char *)NLMSG_DATA(nlh);
  printk("[kernel space] data receive from user: '%s'\n", data);
  pid = nlh->nlmsg_pid;
  printk("[kernel space] user_pid = %d\n", pid);

  int i;
  switch (data[0]) {
  case 'a':
    if (rule_num < 100) {
      rules[rule_num] = (struct filter_rule) * (struct filter_rule *)(data + 1);
      printk("src_ip:%x src_mask:%d dst_ip:%x dst_mask:%d protocol:%d",
             rules[rule_num].src_ip, rules[rule_num].src_mask,
             rules[rule_num].dst_ip, rules[rule_num].dst_mask,
             rules[rule_num].protocol);
      rule_num += 1;
    }
    break;
  case 'l':
    for (i = 0; i < rule_num; ++i) {
      char tmp[256];
      int tmp_len = 0;
      memset(tmp, 0, sizeof(tmp));
      // sprintf(tmp, "%d", i + 1);
      memcpy(tmp, &i, sizeof(i));
      tmp_len = sizeof(i);
      memcpy(tmp + tmp_len, &rules[i], sizeof(rules[i]));
      tmp_len += sizeof(rules[i]);
      nltest_ksend(tmp, tmp_len, pid);
    }
    break;
  case 'L':
    break;
  case 's':
    break;
  case 'r':
    if (rule_num > 0) {
      rule_num -= 1;
    }
    break;
  default:
    break;
  }
  nltest_ksend(end, sizeof(end), pid);
}

struct netlink_kernel_cfg nltest_cfg = {
    0,            // groups
    0,            // flags
    nltest_krecv, // input
    NULL,         // cb_mutex
    NULL,         // bind
    NULL,         // unbind
    NULL,         // compare
};

static int kexec_test_init(void) {
  printk("kexec test start ...\n");
  /*
  test.src_ip = in_aton("192.168.203.132");
  printk("ipip:%x", test.src_ip);
  test.src_port = 22;
  test.dst_ip = in_aton("192.168.203.1");
  test.dst_port = 58245;
  test.protocol = IPPROTO_TCP;
  test.action = 1;
  test.record = 1;
  */

  rules[0].src_ip = in_aton("0.0.0.0");
  rules[0].src_port = 0;
  printk("ipip:%x", rules[0].src_ip);
  rules[0].dst_ip = in_aton("0.0.0.0");
  rules[0].dst_port = 0;
  rules[0].src_mask = 0;
  rules[0].dst_mask = 0;
  rules[0].protocol = IPPROTO_TCP;
  rules[0].action = 1;
  rules[0].record = 1;
  rule_num += 1;
  state_tables =
      (struct state_ *)kmalloc((1 << 8) * sizeof(struct state_), GFP_KERNEL);

  nfho_in.hook = hook_func;
  // nfho_in.owner = NULL;
  nfho_in.pf = PF_INET;
  nfho_in.hooknum = NF_INET_PRE_ROUTING;
  nfho_in.priority = NF_IP_PRI_FIRST;

  nf_register_hook(&nfho_in); /// 注册一个钩子函数

  nfho_out.hook = hook_func;
  // nfho_out.owner = NULL;
  nfho_out.pf = PF_INET;
  nfho_out.hooknum = NF_INET_LOCAL_OUT;
  nfho_out.priority = NF_IP_PRI_FIRST;

  nf_register_hook(&nfho_out); /// 注册一个钩子函数

  // for netlink
  nlsk = netlink_kernel_create(&init_net, NETLINK_TEST, &nltest_cfg);
  if (!nlsk) {
    printk("can not create a netlink socket\n");
    return -1;
  }
  printk("netlink_kernel_create() success, nlsk = %p\n", nlsk);
  return 0;
}

static void kexec_test_exit(void) {
  printk("kexec test exit ...\n");
  nf_unregister_hook(&nfho_in);
  nf_unregister_hook(&nfho_out);
  sock_release(nlsk->sk_socket);
}

module_init(kexec_test_init);
module_exit(kexec_test_exit);
