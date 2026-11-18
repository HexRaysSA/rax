// What the entry of an executable of a portable program does once it has a
// runtime, whichever way it came by one: linked into the executable
// (launcher.c) or found installed and loaded (bootstrap.c).
#ifndef RAX_PORTABLE_LAUNCH_H
#define RAX_PORTABLE_LAUNCH_H

#include "rax_portable_extensions_v1.h"

// The functions of the runtime that launching uses.
typedef struct RaxLaunchRuntime {
  RaxPortableStatusV1 (*context_create)(const RaxPortableConfigV1 *, RaxPortableHandleV1 *);
  RaxPortableStatusV1 (*context_files)(RaxPortableHandleV1, RaxPortableBytesV1);
  RaxPortableStatusV1 (*module_verify)(RaxPortableHandleV1, RaxPortableBytesV1, RaxPortableHandleV1 *);
  RaxPortableStatusV1 (*module_link)(RaxPortableHandleV1, const RaxPortableHandleV1 *, uint64_t,
                                     RaxPortableHandleV1 *);
  RaxPortableStatusV1 (*process_create)(RaxPortableHandleV1, RaxPortableHandleV1, RaxPortableBytesV1,
                                        RaxPortableHandleV1 *);
  RaxPortableStatusV1 (*process_run)(RaxPortableHandleV1, RaxPortableHandleV1 *);
  RaxPortableStatusV1 (*process_join)(RaxPortableHandleV1, RaxPortablePollV1 *);
  RaxPortableStatusV1 (*record_read)(RaxPortableHandleV1, RaxPortableBufferV1 *);
  RaxPortableStatusV1 (*release)(RaxPortableHandleV1);
} RaxLaunchRuntime;

// The status of a process whose program did not run to an end of its own.
enum { RAX_LAUNCH_NOT_COMPLETED = 125 };

// Run the program this executable carries, with this process's arguments,
// and return the status the process is to end with. Does not return if the
// program aborts.
int rax_launch(const RaxLaunchRuntime *runtime, int argc, char **argv);

// Say on standard error, as a line of JSON, why the program was not run:
// a code and what is known beyond it. Returns RAX_LAUNCH_NOT_COMPLETED.
int rax_launch_refused(const char *code, const char *detail);

// The file this process was started from; null if it cannot be told.
char *rax_launch_own_path(void);

#endif
