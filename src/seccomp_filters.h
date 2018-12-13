/*
 * teabox - A tiny sandbox.  
 * 
 * teabox hooks execve() and activates seccomp filters for new processes. 
 * 
 * Copyright (c) 2018 aintahydra <aintahydra@gmail.com> 
 * 
 * Licensed under the GPLv2. 
 *
 * NOTE: Referred the seccomp tutorial by outflux,
 *       which can be found at https://outflux.net/teach-seccomp
 *
 */
#ifndef _SECCOMP_FILETERS_H
#define _SECCOMP_FILETERS_H

#include <linux/unistd.h>
#include <linux/audit.h>
#include <linux/filter.h>

// seccomp
#ifdef HAVE_LINUX_SECCOMP_H
# include <linux/seccomp.h>
#endif

#ifndef PR_SET_NO_NEW_PRIVS
# define PR_SET_NO_NEW_PRIVS 38
#endif

#ifndef PR_SET_SECCOMP
# define PR_SET_SECCOMP 22
#endif

// taken from the chromium/minijail project
#ifndef SECCOMP_MODE_FILTER
# define SECCOMP_MODE_FILTER	2 /* uses user-supplied filter. */
# define SECCOMP_RET_KILL	0x00000000U /* kill the task immediately */
# define SECCOMP_RET_TRAP	0x00030000U /* disallow and force a SIGSYS */
# define SECCOMP_RET_ERRNO	0x00050000U /* return -1 and errno */
# define SECCOMP_RET_ALLOW	0x7fff0000U /* allow */
# define SECCOMP_RET_DATA	0x0000ffffU /* mask for return value */
  struct seccomp_data {
    int nr;
    __u32 arch;
    __u64 instruction_pointer;
    __u64 args[6];
  };
#endif

#define syscall_nr (offsetof(struct seccomp_data, nr))
#define arch_nr (offsetof(struct seccomp_data, arch))

#if defined(__i386__)
# define REG_SYSCALL	REG_EAX
# define ARCH_NR	AUDIT_ARCH_I386
#elif defined(__x86_64__)
# define REG_SYSCALL	REG_RAX
# define ARCH_NR	AUDIT_ARCH_X86_64
#else
# warning "Platform does not support seccomp filter yet"
# define REG_SYSCALL	0
# define ARCH_NR	0
#endif


#ifndef __NR_seccomp
# if defined(__x86_64__)
#  define __NR_seccomp 317
# endif
#endif
#ifndef SECCOMP_SET_MODE_STRICT
#define SECCOMP_SET_MODE_STRICT 0
#endif
#ifndef SECCOMP_SET_MODE_FILTER
#define SECCOMP_SET_MODE_FILTER 1
#endif

// BPF Statements
#define VALIDATE_ARCHITECTURE \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, arch_nr), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ARCH_NR, 1, 0), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL)

#define EXAMINE_SYSCALL \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, syscall_nr)

#define ALLOW_SYSCALL(name) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_##name, 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)

#define KILL_PROCESS \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL)

/* White lists of syscalls */
/* #define MAX_TEABOX_FILTERS 10 */

enum tb_filter_sort {
	TBF_MUNDANE,
	TBF_SIMPLE_ELF,
	TBF_TRIVIAL_PYTHON,
		TBF_NETWORKING_PYTHON,
};

int set_filterset(struct sock_fprog *fprog, enum tb_filter_sort sort);

#endif /* _SECCOMP_FILETERS_H */
