#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(void)
{
  int i;

  char *cmd[] = {"/bin/echo", "Hello", 0};
  
  for (i = 0; i < 10; i++) {
    printf("%d\n", getpid() );
    execve("echo", cmd, NULL);
    sleep(1); // 1sec
  }
  return 0;
}
