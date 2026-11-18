// Launching the program an executable carries; see launch.h.
//
// The executable has the program in a section of its own (see
// tools/smir-clang/smirpack.py). It reads itself, hands itself to the
// runtime, which finds the program in it as in any carrier, and runs it.
// The modules the program is linked with when it is loaded, if it needs
// any, are in further sections, and are linked with it here:
//
// - The program's arguments are this process's, and its standard streams.
// - Its files are those under the directory it is started in, which is the
//   root of every path it uses.
// - It runs as code for this machine where the runtime compiles any, and is
//   interpreted otherwise.
// - It ends as the program ends: with its status, or by aborting. If the
//   program faults, a line of JSON on standard error says how and the
//   status is 125.

// `readlink` is of POSIX, not of ISO C.
#if !defined(__APPLE__) && !defined(_WIN32)
#define _XOPEN_SOURCE 700
#endif

#include "launch.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__APPLE__)
#include <mach-o/dyld.h>
#include <mach-o/getsect.h>
#include <mach-o/ldsyms.h>
#elif defined(_WIN32)
#include <windows.h>
#else
#include <unistd.h>
#endif

int rax_launch_refused(const char *code, const char *detail) {
  fprintf(stderr, "{\"status\":\"rejected\",\"class\":\"launch\",\"code\":\"%s\",\"detail\":\"", code);
  // The detail may be a path or a message of the system's.
  for (const unsigned char *at = (const unsigned char *)detail; *at; at++) {
    if (*at == '"' || *at == '\\')
      fprintf(stderr, "\\%c", *at);
    else if (*at < 0x20)
      fprintf(stderr, "\\u%04x", *at);
    else
      fputc(*at, stderr);
  }
  fprintf(stderr, "\"}\n");
  return RAX_LAUNCH_NOT_COMPLETED;
}

static int fail(const char *what, uint32_t status) {
  char detail[32];
  snprintf(detail, sizeof detail, "status %u", status);
  return rax_launch_refused(what, detail);
}

char *rax_launch_own_path(void) {
  static char path[4096];
#if defined(__APPLE__)
  uint32_t size = sizeof path;
  return _NSGetExecutablePath(path, &size) == 0 ? path : 0;
#elif defined(_WIN32)
  DWORD length = GetModuleFileNameA(0, path, sizeof path);
  return length > 0 && length < sizeof path ? path : 0;
#else
  ssize_t length = readlink("/proc/self/exe", path, sizeof path - 1);
  if (length <= 0)
    return 0;
  path[length] = 0;
  return path;
#endif
}

// A whole file; `*size` is how long it is.
static uint8_t *contents(const char *path, uint64_t *size) {
  FILE *file = fopen(path, "rb");
  if (!file)
    return 0;
  uint8_t *bytes = 0;
  if (fseek(file, 0, SEEK_END) == 0) {
    long length = ftell(file);
    rewind(file);
    bytes = length > 0 ? malloc((size_t)length) : 0;
    if (bytes && fread(bytes, 1, (size_t)length, file) != (size_t)length) {
      free(bytes);
      bytes = 0;
    }
    *size = (uint64_t)length;
  }
  fclose(file);
  return bytes;
}

static RaxPortableBytesV1 text(const char *characters) {
  RaxPortableBytesV1 bytes = {(const uint8_t *)characters, strlen(characters)};
  return bytes;
}

// The most modules a program is linked with here.
enum { MOST_LIBRARIES = 64 };

#if !defined(__APPLE__) && !defined(_WIN32)
// In an ELF executable, where the modules the program is linked with are:
// a table that whoever links the executable provides with them
// (smirpack.py), each module's address and length, ended by a null
// address.
extern const struct RaxLaunchLibrary {
  const uint8_t *data;
  uint64_t length;
} rax_smir_libraries[];
#endif

// One of the modules the program is linked with, as this process has it
// mapped; no bytes if there are not that many. In a Mach-O executable they
// are the sections `__needs0`, `__needs1` and so on of the segment the
// program is in; in an ELF executable, the entries of the table above.
// None is looked for in a PE executable yet.
static RaxPortableBytesV1 library(unsigned index) {
  RaxPortableBytesV1 bytes = {0, 0};
#if defined(__APPLE__)
  char name[17];
  unsigned long size = 0;
  snprintf(name, sizeof name, "__needs%u", index);
  bytes.data = getsectiondata(&_mh_execute_header, "__SMIR", name, &size);
  bytes.length = bytes.data ? size : 0;
#elif defined(_WIN32)
  (void)index;
#else
  // The entries before this one are there, since each was asked for first.
  bytes.data = rax_smir_libraries[index].data;
  bytes.length = bytes.data ? rax_smir_libraries[index].length : 0;
#endif
  return bytes;
}

// The program of this executable as a module of `context`: what the file
// carries, linked with the modules in the sections beside it if there are
// any.
static uint32_t load(const RaxLaunchRuntime *runtime, RaxPortableHandleV1 context, RaxPortableBytesV1 whole,
                     RaxPortableHandleV1 *program) {
  RaxPortableHandleV1 modules[1 + MOST_LIBRARIES];
  // How many of them are verified.
  uint64_t count = 0;
  uint32_t status = runtime->module_verify(context, whole, &modules[0]);
  while (status == 0 && ++count <= MOST_LIBRARIES) {
    RaxPortableBytesV1 bytes = library((unsigned)count - 1);
    if (!bytes.data)
      break;
    status = runtime->module_verify(context, bytes, &modules[count]);
  }
  if (status == 0 && count == 1) {
    *program = modules[0];
    return 0;
  }
  if (status == 0)
    status = runtime->module_link(context, modules, count, program);
  // The linked program keeps what it needs of them.
  for (uint64_t index = 0; index < count; index++)
    runtime->release(modules[index]);
  return status;
}

// Whether a record's reason is `name`, and the number after its `"code":`.
static int has_reason(const char *record, const char *name) {
  const char *reason = strstr(record, "\"reason\":\"");
  return reason && strncmp(reason + 10, name, strlen(name)) == 0 && reason[10 + strlen(name)] == '"';
}

static long code_of(const char *record) {
  const char *code = strstr(record, "\"code\":");
  return code ? strtol(code + 7, 0, 10) : RAX_LAUNCH_NOT_COMPLETED;
}

int rax_launch(const RaxLaunchRuntime *runtime, int argc, char **argv) {
  uint64_t size = 0;
  char *path = rax_launch_own_path();
  uint8_t *image = path ? contents(path, &size) : 0;
  if (!image)
    return fail("LAUNCH_SELF", 0);

  // Everything the runtime has to grant.
  RaxPortableBytesV1 grants[] = {text("clock"), text("file"), text("memory"),
                                 text("process"), text("sync"), text("thread")};
  RaxPortableConfigV1 config = {sizeof config, 1};
  config.capabilities = grants;
  config.capability_count = sizeof grants / sizeof grants[0];
  RaxPortableBytesV1 whole = {image, size};
  RaxPortableHandleV1 context, module, process, request;
  uint32_t status = 0;
  // Code for this machine first; where the runtime has none, interpreted.
  static const char *const profiles[] = {"native", "interpreter"};
  for (int choice = 0; choice < 2; choice++) {
    config.profile = text(profiles[choice]);
    status = runtime->context_create(&config, &context);
    if (status != 0)
      return fail("LAUNCH_CONTEXT", status);
    status = load(runtime, context, whole, &module);
    if (status != 95)
      break;
    runtime->release(context);
  }
  free(image);
  if (status != 0)
    return fail("LAUNCH_MODULE", status);
  status = runtime->context_files(context, text("."));
  if (status != 0)
    return fail("LAUNCH_FILES", status);

  // The spawn record: revision 1, this module, the arguments, and nothing
  // else.
  size_t needed = 4 + 32 + 4 + 12;
  for (int index = 0; index < argc; index++)
    needed += 4 + strlen(argv[index]);
  uint8_t *spawn = calloc(1, needed), *at = spawn;
  if (!spawn)
    return fail("LAUNCH_MEMORY", 12);
  uint32_t word = 1;
  memcpy(at, &word, 4);
  at += 4 + 32;
  word = (uint32_t)argc;
  memcpy(at, &word, 4);
  at += 4;
  for (int index = 0; index < argc; index++) {
    word = (uint32_t)strlen(argv[index]);
    memcpy(at, &word, 4);
    memcpy(at + 4, argv[index], word);
    at += 4 + word;
  }
  RaxPortableBytesV1 record = {spawn, needed};
  status = runtime->process_create(context, module, record, &process);
  free(spawn);
  if (status != 0)
    return fail("LAUNCH_PROCESS", status);
  status = runtime->process_run(process, &request);
  if (status != 0)
    return fail("LAUNCH_RUN", status);
  RaxPortablePollV1 ended = {sizeof ended, 1};
  status = runtime->process_join(process, &ended);
  if (status != 0)
    return fail("LAUNCH_JOIN", status);

  char how[512] = {0};
  RaxPortableBufferV1 buffer = {(uint8_t *)how, sizeof how - 1, 0};
  status = runtime->record_read(ended.result, &buffer);
  if (status != 0)
    return fail("LAUNCH_RECORD", status);
  if (has_reason(how, "normal"))
    return (int)(code_of(how) & 0xff);
  fflush(stdout);
  if (has_reason(how, "abort"))
    abort();
  fprintf(stderr, "%s\n", how);
  return RAX_LAUNCH_NOT_COMPLETED;
}
