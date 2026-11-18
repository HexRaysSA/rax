// The entry of an executable that carries its program and not its runtime:
// it finds a runtime that is installed on the machine, makes sure it is one
// the program can run with, and hands over to it.
//
// Such an executable is this file and launch.c, with the program in a
// section of its own (see tools/smir-clang/smirpack.py --installed). The
// runtime is the shared library of crates/smir-portable-capi.
//
// Where the runtime is looked for, in this order; the first of these that
// is configured is the one, and if the runtime is not there, cannot be
// loaded or is not one the program runs with, the program is not run:
// nothing further is tried.
//
// 1. The absolute path the executable was built with (RAX_RUNTIME_PATH),
//    if it was built with one.
// 2. RAX_RUNTIME_RELATIVE from the directory the executable is in, if
//    there is such a file: by default `../lib/rax/` and the library's name.
// 3. The path in the first line of the installation record, a file at the
//    absolute path RAX_INSTALLATION_RECORD, if there is such a file.
//
// Nothing else is consulted: not the working directory, not the
// environment, not the system's library search path. The path is resolved
// to the file it names, that file is loaded, and every question is then put
// to what was loaded, which is also what runs the program: a file put in
// its place afterwards changes nothing.
//
// The runtime must have the major version of the host interface this file
// was compiled against, the same or a later minor version, at least the
// revision RAX_RUNTIME_REVISION, and the executable profile of the
// program; and, if the executable was built with RAX_RUNTIME_IDENTITY (64
// hexadecimal digits), exactly that implementation identity. The catalogs
// of helpers and services are compared when the program is verified: each
// of its imports quotes the catalog it is from.

// `realpath`, `access` and `PATH_MAX` are of POSIX, not of ISO C.
#if !defined(__APPLE__) && !defined(_WIN32)
#define _XOPEN_SOURCE 700
#endif

#include "launch.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__APPLE__)
#define RAX_RUNTIME_NAME "librax_smir_portable_capi.dylib"
#define RAX_DEFAULT_RECORD "/Library/Application Support/RAX/portable-runtime"
#else
#define RAX_RUNTIME_NAME "librax_smir_portable_capi.so"
#define RAX_DEFAULT_RECORD "/etc/rax/portable-runtime"
#endif
#ifndef RAX_RUNTIME_RELATIVE
#define RAX_RUNTIME_RELATIVE "../lib/rax/" RAX_RUNTIME_NAME
#endif
#ifndef RAX_INSTALLATION_RECORD
#define RAX_INSTALLATION_RECORD RAX_DEFAULT_RECORD
#endif
#ifndef RAX_RUNTIME_REVISION
#define RAX_RUNTIME_REVISION 0
#endif

#if defined(_WIN32)

int main(void) {
  return rax_launch_refused("LAUNCH_RUNTIME_NONE", "an installed runtime is not looked for on this system yet");
}

#else

#include <dlfcn.h>
#include <limits.h>
#include <unistd.h>

// The runtime's file by the first candidate that is configured, as the path
// that was configured; null, with the refusal printed, if none is or the
// one that is names nothing usable.
static const char *configured(char *room, size_t size) {
#ifdef RAX_RUNTIME_PATH
  (void)room, (void)size;
  return RAX_RUNTIME_PATH;
#else
  // Beside the executable: from the directory of the file it really is.
  char own[PATH_MAX];
  const char *started = rax_launch_own_path();
  if (!started || !realpath(started, own)) {
    rax_launch_refused("LAUNCH_SELF", "the executable's own path");
    return 0;
  }
  char *name = strrchr(own, '/');
  *(name ? name + 1 : own) = 0;
  if ((size_t)snprintf(room, size, "%s%s", own, RAX_RUNTIME_RELATIVE) < size && access(room, F_OK) == 0)
    return room;
  // The administrator's record: a file whose first line is the path.
  FILE *record = fopen(RAX_INSTALLATION_RECORD, "r");
  if (!record) {
    rax_launch_refused("LAUNCH_RUNTIME_NONE", "no runtime is installed");
    return 0;
  }
  char *line = fgets(room, (int)size, record);
  fclose(record);
  if (!line || !strchr(line, '\n')) {
    rax_launch_refused("LAUNCH_RUNTIME_RECORD", RAX_INSTALLATION_RECORD);
    return 0;
  }
  *strchr(line, '\n') = 0;
  return line;
#endif
}

// One of the runtime's functions; null, with the refusal printed, if what
// was loaded has no such function.
static void *function(void *loaded, const char *name) {
  void *found = dlsym(loaded, name);
  if (!found)
    rax_launch_refused("LAUNCH_RUNTIME_MALFORMED", name);
  return found;
}

// Whether the runtime that was loaded is one the program runs with; the
// refusal is printed if it is not.
static int suits(void *loaded) {
  RaxPortableStatusV1 (*describe)(RaxPortableRuntimeX1 *) =
      (RaxPortableStatusV1(*)(RaxPortableRuntimeX1 *))function(loaded, "rax_portable_x1_runtime");
  if (!describe)
    return 0;
  RaxPortableRuntimeX1 runtime = {sizeof runtime, 1};
  if (describe(&runtime) != 0)
    return rax_launch_refused("LAUNCH_RUNTIME_MALFORMED", "the runtime does not describe itself"), 0;
  char found[96];
  snprintf(found, sizeof found, "interface %u.%u, revision %u, profile %u", runtime.abi_major, runtime.abi_minor,
           runtime.revision, runtime.profile);
  if (runtime.abi_major != RAX_PORTABLE_ABI_MAJOR || runtime.abi_minor < RAX_PORTABLE_ABI_MINOR ||
      runtime.revision < RAX_RUNTIME_REVISION || runtime.profile != RAX_PORTABLE_PROFILE)
    return rax_launch_refused("LAUNCH_RUNTIME_VERSION", found), 0;
#ifdef RAX_RUNTIME_IDENTITY
  char identity[65];
  for (int index = 0; index < 32; index++)
    snprintf(identity + 2 * index, 3, "%02x", runtime.implementation[index]);
  if (strcmp(identity, RAX_RUNTIME_IDENTITY) != 0)
    return rax_launch_refused("LAUNCH_RUNTIME_IDENTITY", identity), 0;
#endif
  return 1;
}

int main(int argc, char **argv) {
  char room[PATH_MAX], resolved[PATH_MAX];
  const char *path = configured(room, sizeof room);
  if (!path)
    return RAX_LAUNCH_NOT_COMPLETED;
  // An absolute path, and the file it names in the end.
  if (path[0] != '/' || !realpath(path, resolved))
    return rax_launch_refused("LAUNCH_RUNTIME_MISSING", path);
  void *loaded = dlopen(resolved, RTLD_NOW | RTLD_LOCAL);
  if (!loaded) {
    const char *why = dlerror();
    return rax_launch_refused("LAUNCH_RUNTIME_LOAD", why ? why : resolved);
  }
  if (!suits(loaded))
    return RAX_LAUNCH_NOT_COMPLETED;
  static const char *const names[] = {
      "rax_portable_v1_context_create", "rax_portable_x1_context_files", "rax_portable_v1_module_verify",
      "rax_portable_x1_module_link",    "rax_portable_v1_process_create", "rax_portable_v1_process_run",
      "rax_portable_v1_process_join",   "rax_portable_v1_record_read",   "rax_portable_v1_release",
  };
  // The structure is nothing but pointers to functions, in this order.
  union {
    RaxLaunchRuntime runtime;
    void *functions[sizeof names / sizeof names[0]];
  } found;
  _Static_assert(sizeof found.runtime == sizeof found.functions, "one pointer for each name");
  for (size_t index = 0; index < sizeof names / sizeof names[0]; index++)
    if (!(found.functions[index] = function(loaded, names[index])))
      return RAX_LAUNCH_NOT_COMPLETED;
  return rax_launch(&found.runtime, argc, argv);
}

#endif
