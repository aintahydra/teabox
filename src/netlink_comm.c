/*
 * teabox - A tiny sandbox.  
 * 
 * teabox hooks execve() and activates seccomp filters for new processes. 
 * 
 * Copyright (c) 2018 aintahydra <aintahydra@gmail.com> 
 * 
 * Licensed under the GPLv2. 
 */

/* netlink socket, created in the module_init() */
//struct sock *nl_sk = NULL;

#include "netlink_comm.h"

//struct sock *netlink_socket = NULL;
// int daemon_pid;

/*
static void tb_init_recv_pol(struct sk_buff *skb)
{
	printk("Entering: %s\n", __FUNCTION__);
	
	struct nlmsghdr *nlh;
	//access the data through
	nlh=(struct nlmsghdr*)skb->data;

	// void *NLMSG_DATA(strct nlmsghdr *nlh)
	printk(KERN_INFO "received policy payload:%s from the sender(%d)\n", \
	       (char*)nlmsg_data(nlh), nlh->nlmsg_pid);

	//return 1;
}
*/

/**
 * tb_recv_pol() - receive a seccomp policy from the policy daemon
 * @skb: the socket buffer that has the received message
 */
static int tb_recv_pol(struct sk_buff *skb)
{
	struct nlmsghdr *nlh;
	//access the data through
	nlh=(struct nlmsghdr*)skb->data;

	// void *NLMSG_DATA(strct nlmsghdr *nlh)
	printk(KERN_INFO "received policy payload:%s from the sender(%d)\n", \
	       (char*)nlmsg_data(nlh), nlh->nlmsg_pid);

	return 1;
}

/**
 * tb_request_policy() - request the policy daemon a seccomp policy
 * @target: target program information 
 */
static void tb_req_pol(int target)
{
	char *req_msg="target info";
	int req_msg_len = strlen(req_msg);

	int daemon_pid = 0;
	int res;

	struct nlmsghdr *nlh;
	struct sk_buff *skb_out;
	skb_out = nlmsg_new(req_msg_len, 0);
	if(!skb_out) {
		printk(KERN_ERR "Failed to allocate a socket buffer for requesting a policy\n");
		return;
	} 
	nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, req_msg_len, 0);  
	NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */
	strncpy(nlmsg_data(nlh), req_msg, req_msg_len);
	res = nlmsg_unicast(netlink_socket, skb_out, daemon_pid);

	if(res < 0)
		printk(KERN_INFO "Error while requesting policy\n");
}
