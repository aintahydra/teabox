
#include<stdio.h>
#include<unistd.h>

int main (void) {
  printf("redirecting stderr to stdout\n");
  dup2(1,2);
  printf("dup2 done\n");
  return 0;
}
