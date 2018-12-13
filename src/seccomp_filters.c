/*
 * teabox - A tiny sandbox.  
 * 
 * teabox hooks execve() and activates seccomp filters for new processes. 
 * 
 * Copyright (c) 2018 aintahydra <aintahydra@gmail.com> 
 * 
 * Licensed under the GPLv2.
 *
 */
#include <linux/slab.h>
#include "seccomp_filters.h"

/* for trivial executables */
struct sock_filter mundane_filter[] = {
        /* validate architecture. */
        VALIDATE_ARCHITECTURE,
	/* grab the system call number. */
	EXAMINE_SYSCALL,
	/* the followings are allowed syscalls */
	ALLOW_SYSCALL(rt_sigreturn),
#ifdef __NR_sigreturn
	ALLOW_SYSCALL(sigreturn),
#endif
	ALLOW_SYSCALL(exit_group),
	ALLOW_SYSCALL(exit),
	ALLOW_SYSCALL(read),
	ALLOW_SYSCALL(write),
	ALLOW_SYSCALL(fstat),
	ALLOW_SYSCALL(mmap),
	ALLOW_SYSCALL(rt_sigprocmask),
	ALLOW_SYSCALL(rt_sigaction),
	ALLOW_SYSCALL(nanosleep),
	KILL_PROCESS,
};

/* for trivial elf executables */
struct sock_filter simple_elf_filter[] = {
        VALIDATE_ARCHITECTURE,
	EXAMINE_SYSCALL,
	ALLOW_SYSCALL(access),
	/*ALLOW_SYSCALL(arch_prctl),*/
	ALLOW_SYSCALL(brk),
	ALLOW_SYSCALL(close),
	ALLOW_SYSCALL(execve),
	ALLOW_SYSCALL(fstat),
	ALLOW_SYSCALL(mmap),
	ALLOW_SYSCALL(mprotect),
	ALLOW_SYSCALL(munmap),
	ALLOW_SYSCALL(openat),
	ALLOW_SYSCALL(read),
	ALLOW_SYSCALL(write),
	KILL_PROCESS,
};

/* for trivial python scripts */
struct sock_filter trivial_python_filter[] = {
        VALIDATE_ARCHITECTURE,
	EXAMINE_SYSCALL,
	ALLOW_SYSCALL(access),
	/*ALLOW_SYSCALL(arch_prctl),*/
	ALLOW_SYSCALL(brk),
	ALLOW_SYSCALL(close),
	ALLOW_SYSCALL(execve),
	ALLOW_SYSCALL(fstat),
	ALLOW_SYSCALL(getcwd),
	ALLOW_SYSCALL(getdents),
	ALLOW_SYSCALL(getegid),
	ALLOW_SYSCALL(geteuid),
	ALLOW_SYSCALL(getgid),
	ALLOW_SYSCALL(getpid),
	ALLOW_SYSCALL(getuid),
	ALLOW_SYSCALL(ioctl),
	ALLOW_SYSCALL(lseek),
	ALLOW_SYSCALL(lstat),	
	ALLOW_SYSCALL(mmap),
	ALLOW_SYSCALL(mprotect),
	ALLOW_SYSCALL(munmap),
	ALLOW_SYSCALL(openat),
	ALLOW_SYSCALL(prlimit64),
	ALLOW_SYSCALL(read),
	ALLOW_SYSCALL(readlink),
	ALLOW_SYSCALL(rt_sigaction),
	ALLOW_SYSCALL(rt_sigprocmask),
	ALLOW_SYSCALL(set_robust_list),
	ALLOW_SYSCALL(set_tid_address),
	ALLOW_SYSCALL(stat),
	ALLOW_SYSCALL(sysinfo),
	ALLOW_SYSCALL(write),
	KILL_PROCESS,
};

/* for networking-enabled python scripts (setuid enabled) */
struct sock_filter networking_python_filter[] = {
        VALIDATE_ARCHITECTURE,
	EXAMINE_SYSCALL,
	ALLOW_SYSCALL(access),
	ALLOW_SYSCALL(arch_prctl),
	ALLOW_SYSCALL(brk),
	ALLOW_SYSCALL(bind),
	ALLOW_SYSCALL(capget),
	ALLOW_SYSCALL(capset),
	ALLOW_SYSCALL(clone),
	ALLOW_SYSCALL(close),
	ALLOW_SYSCALL(connect),
	ALLOW_SYSCALL(execve),
	ALLOW_SYSCALL(fstat),
	ALLOW_SYSCALL(getcwd),
	ALLOW_SYSCALL(getdents),
	ALLOW_SYSCALL(getegid),
	ALLOW_SYSCALL(geteuid),
	ALLOW_SYSCALL(getgid),
	ALLOW_SYSCALL(getpid),
	ALLOW_SYSCALL(getppid),
	ALLOW_SYSCALL(getsockname),
	ALLOW_SYSCALL(getsockopt),
	ALLOW_SYSCALL(getuid),
	ALLOW_SYSCALL(ioctl),
	ALLOW_SYSCALL(lseek),
	ALLOW_SYSCALL(lstat),	
	ALLOW_SYSCALL(mmap),
	ALLOW_SYSCALL(mprotect),
	ALLOW_SYSCALL(munmap),
	ALLOW_SYSCALL(openat),
	ALLOW_SYSCALL(poll),
	ALLOW_SYSCALL(prctl),
	ALLOW_SYSCALL(prlimit64),
	ALLOW_SYSCALL(read),
	ALLOW_SYSCALL(readlink),
	ALLOW_SYSCALL(recvfrom),
	ALLOW_SYSCALL(recvmsg),
	ALLOW_SYSCALL(rt_sigaction),
	ALLOW_SYSCALL(rt_sigprocmask),
	ALLOW_SYSCALL(sendmmsg),
	ALLOW_SYSCALL(sendto),
	ALLOW_SYSCALL(set_robust_list),
	ALLOW_SYSCALL(set_tid_address),
	ALLOW_SYSCALL(setitimer),
	ALLOW_SYSCALL(setsockopt),
	ALLOW_SYSCALL(setuid),
	ALLOW_SYSCALL(socket),
	ALLOW_SYSCALL(stat),
	ALLOW_SYSCALL(sysinfo),
	ALLOW_SYSCALL(uname),
	ALLOW_SYSCALL(write),
	KILL_PROCESS,
};

/**
 * set_filterset() - sets up a seccomp filter 
 *
 * @fprog: a filter program to be set
 * @sort: the chosen filter sort
 * Returns: 1 (success) or -1 (fail)
 */
int set_filterset(struct sock_fprog *fprog, enum tb_filter_sort sort)
{
	switch (sort) {
	case TBF_MUNDANE:
		fprog->len =
			(unsigned short)(sizeof(mundane_filter)
					 /sizeof(mundane_filter[0]));
	        fprog->filter = mundane_filter;
	        return 1;
        case TBF_SIMPLE_ELF:
	        fprog->len =
			(unsigned short)(sizeof(simple_elf_filter)
					 /sizeof(simple_elf_filter[0]));
	        fprog->filter = simple_elf_filter;
	        return 1;
        case TBF_TRIVIAL_PYTHON:
		fprog->len =
			(unsigned short)(sizeof(trivial_python_filter)
					 /sizeof(trivial_python_filter[0]));
	        fprog->filter = trivial_python_filter;
	        return 1;
        case TBF_NETWORKING_PYTHON:
		fprog->len =
			(unsigned short)(sizeof(networking_python_filter)
					 /sizeof(networking_python_filter[0]));
	        fprog->filter = networking_python_filter;
	        return 1;
	default:
		return -1;
	}	
}
