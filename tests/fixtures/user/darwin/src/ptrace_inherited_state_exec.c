#define main inherited_main
#include "ptrace_inherited_state.c"
#undef main

int main(int argc, char **argv) {
  if (argc > 1)
    return inherited_main(argc, argv);
  char *args[] = {argv[0], "exec", NULL};
  return inherited_main(2, args);
}
