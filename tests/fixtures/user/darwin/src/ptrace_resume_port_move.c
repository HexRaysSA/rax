#define RESUME_PORT_MAIN resume_port_main
#include "ptrace_resume_port.c"

int main(int argc, char **argv) {
  if (argc > 1) return resume_port_main(argc, argv);
  char *args[] = {argv[0], "move", NULL};
  return resume_port_main(2, args);
}
