#ifndef TEABOX_COMMON_H
#define TEABOX_COMMON_H

/* Netlink protocol (up to 32 sorts, c.f) genetlink supports more protocols than 32) */
/* NETLINK_USERSOCK (2) : Reserved for user mode socket protocols (in linux/netlink.h) */
#define TBNL_PROTOCOL NETLINK_USERSOCK

/* Multicast group ID */
#define TBNL_GROUP 21

void tb_nl_policy_parser(struct sk_buff *skb);
//void tb_nl_send_query(char *query);
void tb_nl_send_query(struct sock*ltb_nl_sk,  char *query);

#endif // TEABOX_COMMON_H

