#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv)
{
  if (argc != 2) {
    fprintf(stderr, "Usage: %s <an_application>\n", argv[0]);
    exit(EXIT_FAILURE);
  }
    
  printf("do_exec.c: execute a software giving some arguments\n");

  char *uargs[] = {"zero", "one", "two", "three", NULL};
  char *uenvs[] = {"uenv0=0", "uenv1=1", NULL};
  return execve(argv[1], uargs, uenvs);
}
