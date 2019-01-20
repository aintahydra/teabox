/*
 * teabox - A tiny sandbox.  
 * 
 * teabox hooks execve() and activates seccomp filters for new processes. 
 * 
 * Copyright (c) 2018 aintahydra <aintahydra@gmail.com> 
 * 
 * Licensed under the GPLv2. 
 */
/* 
 * NOTE: References for netlink are 
 * - binwaheed.blogspot.com/2010/08/after-reading-kernel-source-i-finally
 * - opensourceforu.com/2015/08/netlink-a-communication-mechanism-in-linux
 */
#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>

/* "unit": is normally defined in include/uapi/linux/netlink.h
 * and then used by netlink_kernel_create() */
#define NETLINK_USER 31

//static void nl_recv_msg(struct sk_buff *skb);

struct sock *netlink_socket = NULL;

static void tb_init_recv_pol(struct sk_buff *skb);

