/*
 * teabox - A tiny sandbox.  
 * 
 * teabox hooks execve() and activates seccomp filters for new processes. 
 * 
 * Copyright (c) 2018 aintahydra <aintahydra@gmail.com> 
 * 
 * Licensed under the GPLv2. 
 */
#define pr_fmt(fmt) "TTTTT [" KBUILD_MODNAME "] " fmt

#define MOD_AUTHOR "aintahydra <ainthydra@gmail.com>"
#define MOD_DESC "A module of hooking clone()/execve() and activating a seccomp filter"

#include <linux/binfmts.h> /* MAX_ARG_STRINGS - max # of args */
#include <linux/fs.h>
#include <linux/fs_struct.h> /* path_get(), struct path, struct fs_struct, etc. */ 
#include "ftrace_hook.h"
#include "seccomp_filters.h"
#include "teabox.h"

#ifndef CONFIG_X86_64
# error Only support x86_64 for now
#endif

#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include "netlink_comm.h"


//struct sock *netlink_socket = NULL;


static void netlink_cleanup(void) {

	int rc = 0;

	// unregister faily (fops unregisters automatically)
	rc = genl_unregister_family(&teabox_gnl_family);
	if(rc != 0) {
		printk(KERN_INFO "Failed to unregister netlink family\n");
	}
	return;
}

/* ******************************************************************************* */

/**
 * get_usr_string() - keep a copy of a userland string 
 *
 * @usr_string: a string exists in the userland
 * @maxlen: the maximum length of the userland string
 * Returns: a copied version of @usr_string in an allocated buffer within the kernelland
 * NOTE: requires kfree() of the allocated buffer
 */
static char *get_usr_string(const char __user *usr_string, int maxlen)
{
	char *kernel_strbuf;

	kernel_strbuf = kmalloc(maxlen, GFP_KERNEL);
	if (!kernel_strbuf)
		return NULL;

	if (strncpy_from_user(kernel_strbuf, usr_string, maxlen) < 0) {
		kfree(kernel_strbuf);
		return NULL;
	}

	return kernel_strbuf;
}

/**
 * print_current_stat() - get the current PID
 * 
 * Returns: the current PID
 */
static int print_current_stat(void)
{
        int curpid = current->pid;
	pr_debug("- Current PID: %d", curpid);

	return curpid;
}

/**
 * get_current_working_dir() - get a path to the current working directory
 *
 * @cwd: a pointer directing the CWD string
 * 
 * Returns: the string buffer contains the dentry path
 * 
 * NOTE: requires kfree of the returned buffer
 * NOTE: cwd will be set (side effect) 
 */
static char *get_current_working_dir(char **cwd)
{
	char *cwdbuf;
	struct path pwd;
	get_fs_pwd(current->fs, &pwd);

	cwdbuf = (char *)kmalloc(PATH_MAX, GFP_KERNEL);
	if (!cwdbuf) {
	        pr_debug("Memory allocation error\n");
		return NULL;
	}
	memset(cwdbuf, 0, PATH_MAX);
	*cwd = (char *)dentry_path_raw(pwd.dentry, cwdbuf, PATH_MAX);
	pr_debug("- CWD: %s\n", *cwd);

	return cwdbuf;
}

/**
 * get_env_vars() - list up the environment variables
 *                    
 * @envp: a vector array to the environment variables. It originates from execve().
 * 
 * Returns: the number of environment variables, or -1 (abnormal)
 * 
 */
/* TO-DO: 
 * may need to add check-ups that removes LD_PRELOAD and LD_AUDIT */
static int get_env_vars(const char __user *const __user *envp)
{
	int envnum = 0;
	int len = -1;
char *kernel_envvar;

	for(;;) { /* loop until there's no argument */
		const char __user *eptr; /* it will point to each of arguments */

		int tempret = get_user(eptr, envp+envnum);
		/* get_user returns 0 on success, -EFAULT on error,
		 * On error, the first argument is set to zero */

		if (tempret) {
			pr_debug("Getting an env. variable failed");
			return -1;
		}
		
		if (eptr == 0) {/* no more arguments (Terminating condition) */
			pr_debug("# of total env vars: %d", envnum);
			return envnum;
		}
		
		if (IS_ERR(eptr)) {/* etpr < 0 */
			return -1;
		}
		
		/* length of an argument string */ 
		len = strnlen_user(eptr, MAX_ARG_STRLEN);

	      	if (len <= 0)
			return -1;

		/* keep a copy of the argument in the kernel-land */
		//char *kernel_envvar;
		kernel_envvar = get_usr_string(eptr, MAX_ARG_STRLEN);
		if (NULL != kernel_envvar) {
			pr_debug("-- envv[%d]: %s\n", envnum, kernel_envvar);
			kfree(kernel_envvar);
		} else {
			pr_debug("an environment variable could not be copied, sorry");
			return -1;
		}
		envnum++;
	}

	return envnum;
}

/**
 * check_argvs() - list up the command-line arguments
 *
 * @argv: a vector array to the command-line arguments. It originates from execve().
 * 
 * Returns: 
 *          <=0 : error
 *          1 : rel_path
 *          2 : abolute_path_at_home
 */
/* TO-DO: 
 * It roughly assumes that users' home directory paths includes the string "home". 
 * This has to be reinforced somehow. */
static int check_argvs(const char __user *const __user *argv)
{
	int ret = 0;
       	int argnum = 0;
	int len = -1;
	const char __user *ptr; /* it will point to each of arguments */
	int tempret;
	char *kernel_argstr;
	
	for(;;) { /* loop until there's no argument */
    
		//const char __user *ptr; /* it will point to each of arguments */

		//int tempret;
		tempret = get_user(ptr, argv + argnum);
	
		if (tempret) {
			pr_debug("Getting an argument failed");
			return -1;
		}
		if (ptr == 0) {/* no more arguments (Terminating condition) */
			pr_debug("# of total arguments: %d", argnum);
			return ret;
		}

		if (IS_ERR(ptr)) {/* etpr < 0 */
			return -1;
		}
		
		/* length of the obtained argument */
		len = strnlen_user(ptr, MAX_ARG_STRLEN);

		if (len <= 0) {
			pr_debug("an argument could not be copied from user space, sorry");
			return -1;
		}

		//char *kernel_argstr;
		kernel_argstr = get_usr_string(ptr, MAX_ARG_STRLEN);
		if (argnum == 0) {
			if (kernel_argstr[0] == '.') {
				ret = 1;
				return ret;
			}
			if (strstr(kernel_argstr, "home")) {
				ret = 2;
				return ret;
			}
		}

		if (NULL != kernel_argstr) {
			pr_debug("-- argv[%d]: %s\n", argnum, kernel_argstr);
			kfree(kernel_argstr);
		} else {
			pr_debug("an argument could not be copied, sorry");
			return -1;
		}
		argnum++;
	}

	return ret;
}

static asmlinkage long (*orig_sys_clone)(unsigned long clone_flags,
					 unsigned long newsp,
					 int __user *parent_tidptr,
					 int __user *child_tidptr,
					 unsigned long tls);

static asmlinkage long (*orig_sys_execve)(const char __user *filename,
					  const char __user *const __user *argv,
					  const char __user *const __user *envp);

/**
 * tb_sys_clone() - a new sys_clone
 */
static asmlinkage long tb_sys_clone(unsigned long clone_flags,
				    unsigned long newsp,
				    int __user *parent_tidptr,
				    int __user *child_tidptr,
				    unsigned long tls)
{
	long ret;

	//pr_info("clone() staring up, at PID: %ld\n", current->pid);
	pr_info("clone() staring up, at PID: %d\n", current->pid);
	
	ret = orig_sys_clone(clone_flags, newsp, parent_tidptr,
		child_tidptr, tls);

	pr_info("clone() finishing up, new child thread: %ld\n", ret);

	return ret;
}

/**
 * tb_sys_execve() - a new sys_execve
 */
static asmlinkage long tb_sys_execve(const char __user *filename,
				     const char __user *const __user *argv,
				     const char __user *const __user *envp)
{
	int curpid;
	char *cwd_path = NULL;
	char *cwd_buf = NULL;

	char *kernel_filename;
	bool athome = false;
	int argv0_path = 0;
	struct sock_fprog prog;

	long ret;

	
	static asmlinkage long (*sys_prctl)(int option,
					    unsigned long arg2,
					    unsigned long arg3,
					    unsigned long arg4,
					    unsigned long arg5);

	static asmlinkage long (*sys_seccomp)(unsigned int op,
					      unsigned int flags,
					      const char __user *uargs);

	
	pr_info("execve hooked (pre) ########### ");

	
	sys_prctl = kallsyms_lookup_name("sys_prctl");
	sys_seccomp = kallsyms_lookup_name("sys_seccomp");

	
	//int curpid;
	curpid = print_current_stat();

	//	char *cwd_path = NULL;
	//char *cwd_buf = NULL;

	cwd_buf = get_current_working_dir(&cwd_path);


	if (cwd_path != NULL && strstr(cwd_path, "home"))
		athome = true;
	/* TO-DO: tmp dir and euid would be considered as well */

	//	char *kernel_filename;
	  kernel_filename = get_usr_string(filename, MAX_ARG_STRLEN);
	pr_info("- filename to launch: %s\n", kernel_filename);

	get_env_vars(envp);

	//int argv0_path = 0;
	argv0_path = check_argvs(argv);

	
	//
	// TODO: Here the netlink communication has to be placed
	//
	//
	char *file_category = "This is a category info";
	int rc2 = teabox_send_polreq(file_category);


	//
	//
	//
	//




	

	//struct sock_fprog prog;
	//	if (set_filterset(&prog, TBF_MUNDANE) < 0) {
		if (set_filterset(&prog, TBF_NETWORKING_PYTHON) < 0) {
		pr_debug("filterset error");	
	}

	
	/* apply the filter */
	if ((athome == true && argv0_path == 1 )
	    || argv0_path == 2) {
		pr_info("*** SUSPICIOUS *** ... sandboxing now");

		/* sandboxing */
		/* in case of setuid applications(e.g., ping), 
		 *   PR_SET_NO_NEW_PRIVS must not be included. 
		 * otherwise, PR_SET_NO_NEW_PRIVS should be needed */
		/*
		if (sys_prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
			pr_debug("prctl(NO_NEW_PRIVS) Error");
			goto TEMP2;
			}

		if (sys_prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER,
			      (unsigned long)&prog, 0, 0) < 0) {
			pr_debug("prctl(SECCOMP) Error");
			goto TEMP2;
		}
		*/
	}
  
TEMP2:  
	pr_debug("OK, now call the original one.");

	kfree(cwd_buf);
	kfree(kernel_filename);

	ret = orig_sys_execve(filename, argv, envp);
	pr_info("execve hooked (post) PID: %d ##########", curpid);
	return ret;
}

static struct ftrace_hook replaced_hooks[] = {
	FT_HOOK("sys_clone",  tb_sys_clone,  &orig_sys_clone),
	FT_HOOK("sys_execve", tb_sys_execve, &orig_sys_execve),
};

static int teabox_init(void)
{
	
	int err;

//	struct netlink_kernel_cfg nlcfg = {
//		.input = tb_init_recv_pol,
//	};
	
	printk("Entering: %s\n", __FUNCTION__);

	/* installing hooks */
	err = fh_install_hooks(replaced_hooks, ARRAY_SIZE(replaced_hooks));
	if (err)
		return err;
	
	pr_info("hook installed");

/* ******************************************************************************* */	
	/* preparing netlink communication */
	struct netlink_kernel_cfg nlcfg = {
		.input = teabox_received_msg_handler,
	};

	teabox_nl_sock = netlink_kernel_create(&init_net, NETLINK_USER, &nlcfg);
	if (!teabox_nl_sock) {
		printk(KERN_ALERT "Error creating socket\n");
		return -1;
	}
	/* most drivers use init_net namespace */ 

	/* OLD
	netlink_socket = netlink_kernel_create(&init_net, NETLINK_USER, &nlcfg);
	
	if(!netlink_socket){
		printk(KERN_ALERT "Error creating socket.\n");
		return -1;
	}
	*/	
	/*
	daemon_pid = -1;
	while (daemon_pid != -1) {
		struct sk_buff skbuff;
		tb_revb_pol(skbuff);

		
	}
	*/
	//pr_info("daemon connected");
/* ******************************************************************************* */
	int rc = 0; 

	// register generic netlink family
	// corrected referring: http://www.linuxforums.org/forum/kernel/209698-genl_register_ops-genl_register_family_with_ops-v-v-linux-4-10-a.html

	// an OLDOLD way
	//rc = genl_register_family(&teabox_gnl_family);
	//rc = genl_register_ops(&teabox_gnl_family, &teabox_gnl_ops_polreq);

	// an OLD way
	//rc = genl_register_family_with_ops(&teabox_gnl_family,
	//				   &teabox_gnl_ops_polreq, ARRAY_SIZE(teabox_gnl_ops_polreq));
	
	rc = genl_register_family(&teabox_gnl_family);
	if (rc != 0) {
		printk(KERN_INFO "Failed to register multicast group\n");
		goto fail;
	}
	
	return 0;

fail:
	netlink_cleanup();
	return -EINVAL;
}

module_init(teabox_init);

static void teabox_exit(void)
{
	printk("Entering: %s\n",__FUNCTION__);
	
        // cleaning up up the hook
	fh_remove_hooks(replaced_hooks, ARRAY_SIZE(replaced_hooks));

	// removing the netfilter 
	/* OLD
	netlink_kernel_release(netlink_socket);
	*/
	
	netlink_cleanup();
	
	pr_info("teabox unloaded");
}
module_exit(teabox_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR(MOD_AUTHOR);
MODULE_DESCRIPTION(MOD_DESC);
