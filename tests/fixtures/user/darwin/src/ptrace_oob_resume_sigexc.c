#define OOB_RESUME_MAIN oob_resume_main
#include "ptrace_oob_resume.c"

int main(int argc, char **argv) {
  if (argc > 1)
    return oob_resume_main(argc, argv);
  char *args[] = {argv[0], "sigexc", NULL};
  return oob_resume_main(2, args);
}
