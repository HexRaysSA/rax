#define main suspension_main
#include "ptrace_task_suspend.c"
#undef main

int main(int argc, char **argv) {
  if (argc > 1)
    return suspension_main(argc, argv);
  char *args[] = {argv[0], "exec", NULL};
  return suspension_main(2, args);
}
