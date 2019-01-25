/*
 * teabox - A tiny sandbox.  
 * 
 * teabox hooks execve() and activates seccomp filters for new processes. 
 * 
 * Copyright (c) 2018 aintahydra <aintahydra@gmail.com> 
 * 
 * Licensed under the GPLv2. 
 */

#include "netlink_comm.h"

static int teabox_send_polreq(char *filecategory)
{
	int rc;
	void *msg_head;
	
	struct sk_buff *skb;
	skb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (skb == NULL) {
		printk(KERN_ERR "Failed to construct message\n");
		goto failure;
	}

	/*
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
	NETLINK_CB(skb_out).dst_group = 0; // not in mcast group 
	strncpy(nlmsg_data(nlh), req_msg, req_msg_len);
	res = nlmsg_unicast(netlink_socket, skb_out, daemon_pid);
	
	
	if(res < 0)
		printk(KERN_INFO "Error while requesting policy\n");
	*/

	
	int pid = 0;
	int seq = 0;
	int type = 0;
	int flags = 0;

	/*
	msg_head = genlmsg_put(skb,
			       pid,           // Port ID is whatever
			       seq,           // Sequence number (don't care)
			       type, //genl_family
			       0,
			       flags,
			       TEABOX_GENL_C_POLREQ,
			       1);
	*/
	//void *genlmsg_put(struct sk_buff *skb, u32 portid, u32 seq,
	//	  struct genl_family *family, int flags, u8 cmd);
	msg_head = genlmsg_put(skb, pid, seq, &teabox_gnl_family,
			       flags, TEABOX_GENL_C_POLREQ);
	
	if (msg_head == NULL) {
		rc = -ENOMEM;
		printk(KERN_ERR "Failed to create a generic netlink message\n" );
		goto failure;
	}

	// add attributes
	//if (nla_put_u32(skb, TEABOX_GENL_ATTR_APP_CATEGORY, polreq->category) ||
	rc = nla_put_string(skb, TEABOX_GENL_A_CATEGORY, filecategory);
	if (rc != 0) {
		printk(KERN_ERR "Failed to add attributes to the generic netlink message\n" );
		goto failure;
	}		

	// finalize the message
	genlmsg_end(skb, msg_head);


	rc = nlmsg_unicast(teabox_nl_sock, skb, pid);
	if (rc != 0)
		goto failure;
	//rc = genlmsg_multicast_allns(skb, 0, keymon_mc_group.id, GFP_KERNEL );
	//rc = genlmsg_multicast_allns(skb, 0, teabox_mc_group.id, GFP_KERNEL);

	// If error - fail.
	// ESRCH is "forever alone" case - no one is listening for our messages 
	// and it's ok, since userspace daemon can be unloaded.
	//if (rc && rc != -ESRCH) {
	//	prink( KERN_WARNING, "Failed to send message. rc = %d\n", rc );
        //goto out;
	//}

	//goto out; // FIXME: should rewrite this little spaghetti logic

	return 0;
	
//nla_put_failure:
//	genlmsg_cancel(skb, msg);
failure:
	// Need this to free notification allocated in irq handler
	//kfree(polreq);
	return -1;
}

static void teabox_received_msg_handler(struct sk_buff *skb)
{
	printk("Entering: %s\n", __FUNCTION__);
	
	struct nlmsghdr *nlh;
	//access the data through
	nlh = (struct nlmsghdr*)skb->data;
	int pid = nlh->nlmsg_pid;

	// void *NLMSG_DATA(strct nlmsghdr *nlh)
	printk(KERN_INFO "received msg: %s from the sender(%d)\n", \
	       (char*)nlmsg_data(nlh), pid);

	//return 1;
}






/**
 * tb_recv_pol() - receive a seccomp policy from the policy daemon
 * @skb: the socket buffer that has the received message
 */
 /* for UNICAST
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
 */
/**
 * tb_request_policy() - request the policy daemon a seccomp policy
 * @target: target program information 
 */
  /* for UNICAST
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
	NETLINK_CB(skb_out).dst_group = 0; // not in mcast group 
	strncpy(nlmsg_data(nlh), req_msg, req_msg_len);
	res = nlmsg_unicast(netlink_socket, skb_out, daemon_pid);

	if(res < 0)
		printk(KERN_INFO "Error while requesting policy\n");
}
  */


































/* keymon

// netlink socket, created in the module_init()
//struct sock *nl_sk = NULL;

//struct sock *netlink_socket = NULL;


// keyboard notification ====> policy request

//static void teabox_send_notification(struct work_struct *work)
static void teabox_send_polreq(struct work_struct *work)
{
	//struct keymon_notification *nf = NULL;
	struct teabox_polreq *polreq = NULL;

	struct sk_buff *skb;
	void *msg;

	// what the heck rc is?
	int rc = 0;

	// ---------------------------------------------
	// Dereference keyboard notification parameters
	// ---------------------------------------------
	//nf = container_of( work, struct keymon_notification, ws );
	polreq = container_of(work, struct teabox_policy_request, ws);
	if(!polreq) {
		km_log(KERN_ERR, "Failed to get work struct container.\n");
		return;
	}

	printk(KERN_DEBUG, "cat %d, lev %d\n", polreq->category, polreq->level);
	
	// ----------------------------------------------
	// Construct netlink and generic netlink headers
	// ----------------------------------------------
	skb = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (!skb) {
		printk(KERN_ERR, "Failed to construct message\n");
		goto out;
	}

	msg = genlmsg_put(skb, 
	                  0,           // PID is whatever
	                  0,           // Sequence number (don't care)
	                  &teabox_genl_family, //&keymon_genl_family,   // Pointer to family struct
	                  0,                     // Flags
	                  TEABOX_GENL_CMD_REQPOL //KEYMON_GENL_CMD_NOTIFY // Generic netlink command 
	                  );
	if (!msg) {
		printk( KERN_ERR, "Failed to create generic netlink message\n" );
		goto out;
	}

	// --------------------------------------------
	// Fill attributes 
	// --------------------------------------------
	if (nla_put_u32(skb, TEABOX_GENL_ATTR_APP_CATEGORY, polreq->category) ||
	    nla_put_u32(skb, TEABOX_GENL_ATTR_APP_LEVEL, polreq->level)) {
		goto nla_put_failure;
	}

	// --------------------------
	// Finalize and send message
	// --------------------------
	genlmsg_end(skb, msg);

	//rc = genlmsg_multicast_allns(skb, 0, keymon_mc_group.id, GFP_KERNEL );
	rc = genlmsg_multicast_allns(skb, 0, teabox_mc_group.id, GFP_KERNEL);

	// If error - fail.
	// ESRCH is "forever alone" case - no one is listening for our messages 
	// and it's ok, since userspace daemon can be unloaded.
	if (rc && rc != -ESRCH) {
		prink( KERN_WARNING, "Failed to send message. rc = %d\n", rc );
		goto out;
	}

	goto out; // FIXME: should rewrite this little spaghetti logic

nla_put_failure:
	genlmsg_cancel(skb, msg);
out:
	// Need this to free notification allocated in irq handler
	kfree(polreq);
	return;
}


static int teabox_genl_notify_dump(struct sk_buff *skb, struct netlink_callback *cb) {
	return 0;
}

//param & code is for key press, we don't need em
//static int teabox_exec_nf_cb(struct notifier_block *nb, unsigned long code, void *_param)OB {
//static int teabox_exec_polreq_cb(struct notifier_block *nb, int filecat, int filelev) {
static int teabox_exec_polreq_cb(int filecat, int filelev)
{
	//struct teabox_notifier_param *param = NULL;
	struct teabox_policy_request *polreq = NULL;

	polreq = (struct teabox_policy_request *)kzalloc(size of(struct teabox_policy_request), GFP_ATOMIC);
	if (!polreq) {
		printk(KERN_WARNING, "Failed to submit policy request workqueue\n");
		return NOTIFY_BAD;
	}
	INIT_WORK(&polreq->ws, teabox_send_policy_request);
	
	queue_work(teabox_wq, &polreq->ws);

	//}
	return NOTIFY_DONE;
}

*/
