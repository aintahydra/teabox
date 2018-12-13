//source: https://veritas501.space/2018/05/05/seccomp%E5%AD%A6%E4%B9%A0%E7%AC%94%E8%AE%B0/
//gcc -g simple_syscall.c -o simple_syscall
#include <unistd.h>

int main(void){
	char * argv[] = {"/bin/sh",NULL};
	char * envp[] = {NULL};
	write(1,"i will give you a shell\n",24);
	syscall(59,argv[0],argv,envp);//execve
	return 0;
}
