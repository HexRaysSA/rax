// The entry of an executable that carries its runtime and its program.
//
// Such an executable is this file and the runtime's static library, linked
// by the system's linker, with the program in a section of its own (see
// tools/smir-clang/smirpack.py). It reads itself, hands itself to the
// runtime, which finds the program in it as in any carrier, and runs it:
//
// - The program's arguments are this process's, and its standard streams.
// - Its files are those under the directory it is started in, which is the
//   root of every path it uses.
// - It runs as code for this machine where the runtime compiles any, and is
//   interpreted otherwise.
// - It ends as the program ends: with its status, or by aborting. If the
//   program faults, a line of JSON on standard error says how and the
//   status is 125.
#include "rax_portable_extensions_v1.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__APPLE__)
#include <mach-o/dyld.h>
#elif defined(_WIN32)
#include <windows.h>
#else
#include <unistd.h>
#endif

enum { STATUS_NOT_COMPLETED = 125 };

static int fail(const char *what, uint32_t status) {
  fprintf(stderr, "{\"status\":\"rejected\",\"class\":\"launch\",\"code\":\"%s\",\"detail\":\"status %u\"}\n", what,
          status);
  return STATUS_NOT_COMPLETED;
}

// The file this process was started from; null if it cannot be told.
static char *own_path(void) {
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

// The number after `"code":` in a record, and whether its reason is `name`.
static int has_reason(const char *record, const char *name) {
  const char *reason = strstr(record, "\"reason\":\"");
  return reason && strncmp(reason + 10, name, strlen(name)) == 0 && reason[10 + strlen(name)] == '"';
}

static long code_of(const char *record) {
  const char *code = strstr(record, "\"code\":");
  return code ? strtol(code + 7, 0, 10) : STATUS_NOT_COMPLETED;
}

int main(int argc, char **argv) {
  uint64_t size = 0;
  char *path = own_path();
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
    status = rax_portable_v1_context_create(&config, &context);
    if (status != 0)
      return fail("LAUNCH_CONTEXT", status);
    status = rax_portable_v1_module_verify(context, whole, &module);
    if (status != 95)
      break;
    rax_portable_v1_release(context);
  }
  free(image);
  if (status != 0)
    return fail("LAUNCH_MODULE", status);
  status = rax_portable_x1_context_files(context, text("."));
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
  status = rax_portable_v1_process_create(context, module, record, &process);
  free(spawn);
  if (status != 0)
    return fail("LAUNCH_PROCESS", status);
  status = rax_portable_v1_process_run(process, &request);
  if (status != 0)
    return fail("LAUNCH_RUN", status);
  RaxPortablePollV1 ended = {sizeof ended, 1};
  status = rax_portable_v1_process_join(process, &ended);
  if (status != 0)
    return fail("LAUNCH_JOIN", status);

  char how[512] = {0};
  RaxPortableBufferV1 buffer = {(uint8_t *)how, sizeof how - 1, 0};
  status = rax_portable_v1_record_read(ended.result, &buffer);
  if (status != 0)
    return fail("LAUNCH_RECORD", status);
  if (has_reason(how, "normal"))
    return (int)(code_of(how) & 0xff);
  fflush(stdout);
  if (has_reason(how, "abort"))
    abort();
  fprintf(stderr, "%s\n", how);
  return STATUS_NOT_COMPLETED;
}
