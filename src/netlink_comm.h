#ifndef NETLINK_COMM_H
#define NETLINK_COMM_H

#include <linux/module.h>	/* Needed by all modules */
#include <linux/kernel.h>	/* Needed for KERN_INFO */
#include <linux/version.h>  /* KERNEL_VERSION macro */
#include <linux/init.h>		/* Needed for the init macros */

#include <net/netlink.h>    /* Common Netlink API */
#include <net/genetlink.h>  /* Special Generic Netlink API */

#include <linux/hardirq.h>

//#include "teabox_common.h"

#define tbx_log(level, fmt, args...) printk(level "Keymon: In %s:%d. " fmt, __FUNCTION__, __LINE__, ## args)

static struct sock *teabox_nl_sock = NULL;
#define NETLINK_USER 31

//ref: https://wiki.linuxfoundation.org/networking/generic_netlink_howto
// STEP1: Registering a Family
// (steps : define family -> define the operations -> register the family -> register the operations)


// Step 1) Define Family

#define TEABOX_GENL_FAMILY_NAME "TEABOX_POLREQ"
#define TEABOX_GENL_VERSION 1

// Step 1.1.) attributes
enum _teabox_genl_attributes 
{
	__TEABOX_GENL_A_UNSPEC = 0,
	TEABOX_GENL_A_CATEGORY,
	__TEABOX_GENL_A_MAX,
};
#define TEABOX_GENL_A_MAX (__TEABOX_GENL_A_MAX - 1)

// Step 1.2) attribute policy 
//  used by generic netlink contoller to validate our attributes
static struct nla_policy teabox_genl_policy[TEABOX_GENL_A_MAX + 1] = 
{
	// Notification struct content
	[TEABOX_GENL_A_CATEGORY]    = { .type = NLA_NUL_STRING },
};

/*
// Step 1.3) define family

struct genl_family teabox_gnl_family = {
//.id      = GENL_ID_GENERATE, // Generate ID 
	.hdrsize = 0, // No custom header
	.name    = TEABOX_GENL_FAMILY_NAME, //"teabox" in teabox_common.h
	.version = TEABOX_GENL_VERSION, //"1" in teabox_common.h
	.maxattr = TEABOX_GENL_ATTR_MAX,
	};*/

// Step 2) Define the operations for the family (up to 255 operations)

// Step 2.1) handler (message handling) definitions 

static int teabox_polreq_message_handler(struct sk_buff *skb, struct genl_info *info)
{
	// message handling code
	// return 0 on success
	// return negative on failure
}

// Step 2.2) commands
enum _teabox_genl_commands {
	__TEABOX_GENL_C_UNSPEC,
	TEABOX_GENL_C_POLREQ,
	__TEABOX_GENL_C_MAX,
};

#define TEABOX_GENL_C_MAX (__TEABOX_GENL_C_MAX - 1)

// Step 2.3) operations

// Once registered, this operation calls teabox_genl_polreq() function
//     when TEABOX_GENL_C_POLREQ is sent to the TEABOX_POLREQ family over the Generic Netlink bus 
// this op uses the Netlink attribute policy defined above
static struct genl_ops teabox_gnl_ops_polreq = {
	.cmd = TEABOX_GENL_C_POLREQ,
	.flags = 0,
	.policy = teabox_genl_policy,
	.doit = teabox_polreq_message_handler, 
	.dumpit = NULL,
};

// Step 3) Register the family with the genetlink operations

/* the followings codes should be found in netlink_comm.c
int rc; 
rc = genl_register_family(&teabox_gnl_family);
if (rc != 0)
    goto failure;
*/
//This call registers the new family name with the Generic Netlink mechanism and requests a new channel number which is stored in the genl_family struct, replacing the GENL_ID_GENERATE value. It is important to remember to unregister Generic Netlink families when done as the kernel does allocate resources for each registered family.


// Step 4) Register the operations for the family
/* the following codes should be found in netlink_comm.c
 int rc;
 rc = genl_register_ops(&teabox_gnl_family, &teabox_gnl_ops_polreq);
 if (rc != 0)
     goto failure;
*/
// NOTE: This function doesn't exist past linux 3.12. Up to linux 4.10, use genl_register_family_with_ops(). On 4.10 and later, include a reference to your genl_ops struct as an element in the genl_family struct (element .ops), as well as the number of commands (element .n_ops).
//This call registers the DOC_EXMPL_C_ECHO operation in association with the DOC_EXMPL family. The process is now complete. Other Generic Netlink users can now issue DOC_EXMPL_C_ECHO commands and they will be handled as desired. 

// Therefore the step 1.3) is moved here
// Step 1.3) define family

static const struct genl_ops teabox_gnl_ops[] = {
	{
		.cmd = TEABOX_GENL_C_POLREQ,
		.doit = teabox_polreq_message_handler,
		.policy = teabox_genl_policy,
	}
};

static struct genl_family teabox_gnl_family = {
//.id      = GENL_ID_GENERATE, // Generate ID 
	.hdrsize = 0, // No custom header
	.name    = TEABOX_GENL_FAMILY_NAME, //"teabox" in teabox_common.h
	.version = TEABOX_GENL_VERSION, //"1" in teabox_common.h
	.maxattr = TEABOX_GENL_A_MAX,
	.ops = teabox_gnl_ops,
	.n_ops = ARRAY_SIZE(teabox_gnl_ops),
};

static int teabox_send_polreq(char *filecategory);
static void teabox_received_msg_handler(struct sk_buff *skb);

#endif
