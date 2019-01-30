//references: https://www.linuxjournal.com/article/7356
//references: https://gist.github.com/arunk-s/c897bb9d75a6c98733d6
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <unistd.h>
#include "teabox_nl_common.h"

#define MAX_PAYLOAD 1024

int open_netlink(void)
{
	int sock;
	struct sockaddr_nl addr;
	int group = TBNL_GROUP;

	sock = socket(AF_NETLINK, SOCK_RAW, TBNL_PROTOCOL);
	if (sock < 0) {
		printf("Error creating a socket\n");
		return sock;
	} else {
		printf("Created a socket fd: %d\n", sock);
	}
	
	memset((void *) &addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;
	addr.nl_pid = getpid();

	if (bind(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		printf("Error binding the socket\n");
		return -1;
	}

	if (setsockopt(sock, 270, NETLINK_ADD_MEMBERSHIP, &group, sizeof(group)) < 0) {
		printf("setsockopt < 0\n");
		return -1;
	}

	return sock;
}

int read_request(int sock)
{
	struct sockaddr_nl nladdr;
	struct msghdr msg;
	struct iovec iov;
	char buffer[65536];
	int ret;

	iov.iov_base = (void *) buffer;
	iov.iov_len = sizeof(buffer);
	msg.msg_name = (void *) &(nladdr);
	msg.msg_namelen = sizeof(nladdr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	printf("Ready to receive a policy request\n");
	ret = recvmsg(sock, &msg, 0);
	if (ret < 0) {
		printf("Error receiving a request\n");
	return -1;
	}
	else {
		printf("Got a request: %s\n", (char *)NLMSG_DATA((struct nlmsghdr *) &buffer));
	}
	return 0;
}

void send_policy(int sock)
{
	struct sockaddr_nl src_addr, dest_addr;
	struct msghdr msg;
	struct iovec iov;
	char buffer[65536];
	int ret;

	struct nlmsghdr *nlh = NULL;

	// just in case, set the src address again here
	memset(&src_addr, 0, sizeof(src_addr));
	src_addr.nl_family = AF_NETLINK;
	src_addr.nl_pid = getpid();  //this one
	src_addr.nl_groups = TBNL_GROUP;
    
	memset(&dest_addr, 0, sizeof(dest_addr));
	dest_addr.nl_family = AF_NETLINK;
	dest_addr.nl_pid = 0; // kernel
	dest_addr.nl_groups = TBNL_GROUP;

	nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
	memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
	nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
	nlh->nlmsg_pid = getpid();
	nlh->nlmsg_flags = 0;

	strcpy(NLMSG_DATA(nlh), "Hello");

	iov.iov_base = (void *)nlh;
	iov.iov_len = nlh->nlmsg_len;
	msg.msg_name = (void *)&dest_addr;
	msg.msg_namelen = sizeof(dest_addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	printf("sending: %s\n", (char *)NLMSG_DATA(nlh));
	ret = sendmsg(sock, &msg, 0);
	if (ret < 0)
		printf("Error(%d) sending policy statements\n", ret);

}
	
int main(int argc, char *argv[])
{
	int nls;

	nls = open_netlink();
	if (nls < 0)
		return nls;

	while (1) { // busy waiting
		if (read_request(nls) >= 0) {
			printf("sending back a policy\n");
			send_policy(nls);
		}
	}
  
	return 0;
}
