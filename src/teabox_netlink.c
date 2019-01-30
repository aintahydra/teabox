#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netlink.h>
#include <net/netlink.h>
#include <net/net_namespace.h>
#include "teabox_nl_common.h"

void tb_nl_policy_parser(struct sk_buff *skb)
{
	struct nlmsghdr *nlh;
	int res;
	int pid, seq, nsid;
	kuid_t uid;
	kgid_t gid;

	printk(KERN_INFO "Entering: %s\n", __FUNCTION__);

	nlh = (struct nlmsghdr *)skb->data;

	pid = NETLINK_CREDS(skb)->pid;
        uid = NETLINK_CREDS(skb)->uid;
	gid = NETLINK_CREDS(skb)->gid;
	seq = nlh->nlmsg_seq;
	pr_info("Received a policy statement: %s", (char *)NLMSG_DATA(nlh));
	pr_info("It is sent from [uid:%d] [pid:%d] [gid:%d] in [seq:%d]", (int)uid.val, pid, (int)gid.val, seq);
	if(NETLINK_CB(skb).nsid_is_set)
		pr_info("nsid is set: %d\n", (int)NETLINK_CB(skb).nsid);
	else
		pr_info("nsid is not set\n");
}

void tb_nl_send_query(struct sock *ltb_nl_sk, char *query)
{
  	struct sk_buff *skb;
	struct nlmsghdr *nlh;
	char *msg = "a sample query";
	int msg_size = strlen(msg) + 1;
	int res;

	printk(KERN_INFO "Entering: %s\n", __FUNCTION__);
		
	skb = nlmsg_new(NLMSG_ALIGN(msg_size + 1), GFP_KERNEL);
	if (!skb) {
		pr_err("Error creating skb\n");
		return;
	}

	nlh = nlmsg_put(skb, 0, 1, NLMSG_DONE, msg_size + 1, 0);
	strcpy(nlmsg_data(nlh), msg);

	res = nlmsg_multicast(ltb_nl_sk, skb, 0, TBNL_GROUP, GFP_KERNEL);
	if (res < 0)
		pr_info("Error(%d) sending a query", res);
	else
		pr_info("A query sent.\n");
}
