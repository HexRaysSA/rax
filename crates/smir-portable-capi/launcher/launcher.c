// The entry of an executable that carries its runtime and its program.
//
// Such an executable is this file, launch.c and the runtime's static
// library, linked by the system's linker, with the program in a section of
// its own (see tools/smir-clang/smirpack.py). What it does when it is
// started is in launch.c; the runtime it does it with is the one linked
// into it.
#include "launch.h"

int main(int argc, char **argv) {
  static const RaxLaunchRuntime runtime = {
      rax_portable_v1_context_create, rax_portable_x1_context_files, rax_portable_v1_module_verify,
      rax_portable_x1_module_link,    rax_portable_v1_process_create, rax_portable_v1_process_run,
      rax_portable_v1_process_join,   rax_portable_v1_record_read,   rax_portable_v1_release,
  };
  return rax_launch(&runtime, argc, argv);
}
