// A host in C: it carries the runtime, has a module verified, runs it as a
// process and says how it ended. Arguments: the module's file, then the
// arguments of the program after its name.
#include "rax_portable_extensions_v1.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static RaxPortableBytesV1 bytes_of(const char *text) {
  RaxPortableBytesV1 bytes = {(const uint8_t *)text, strlen(text)};
  return bytes;
}

static void put32(uint8_t **at, uint32_t value) {
  memcpy(*at, &value, 4);
  *at += 4;
}

int main(int argc, char **argv) {
  if (argc < 2)
    return 2;
  FILE *file = fopen(argv[1], "rb");
  if (!file)
    return 2;
  static uint8_t module_bytes[1 << 24];
  size_t module_size = fread(module_bytes, 1, sizeof module_bytes, file);
  fclose(file);

  // What the program may use: its streams, and ending itself.
  RaxPortableBytesV1 grants[] = {bytes_of("file"), bytes_of("process")};
  RaxPortableConfigV1 config = {sizeof config, 1};
  config.capabilities = grants;
  config.capability_count = 2;
  RaxPortableHandleV1 context, module, process, request;
  uint32_t status = rax_portable_v1_context_create(&config, &context);
  printf("context %u\n", status);

  // A structure of another size or version is refused before it is read.
  RaxPortableConfigV1 strange = config;
  strange.version = 2;
  printf("other version %u\n", rax_portable_v1_context_create(&strange, &module));

  RaxPortableBytesV1 image = {module_bytes, module_size};
  printf("module %u\n", rax_portable_v1_module_verify(context, image, &module));
  RaxPortableBytesV1 garbage = bytes_of("not a module");
  printf("garbage %u\n", rax_portable_v1_module_verify(context, garbage, &process));

  // The spawn record: revision, the module (zeros for the one given), the
  // arguments, no environment, no directory, nothing inherited.
  uint8_t spec[4096], *at = spec;
  put32(&at, 1);
  memset(at, 0, 32);
  at += 32;
  put32(&at, (uint32_t)(argc - 1));
  for (int index = 1; index < argc; index++) {
    const char *argument = index == 1 ? "consumer" : argv[index];
    put32(&at, (uint32_t)strlen(argument));
    memcpy(at, argument, strlen(argument));
    at += strlen(argument);
  }
  put32(&at, 0);
  put32(&at, 0);
  put32(&at, 0);
  RaxPortableBytesV1 spawn = {spec, (uint64_t)(at - spec)};
  printf("process %u\n", rax_portable_v1_process_create(context, module, spawn, &process));
  fflush(stdout);

  // What the program writes goes to this program's standard output, while
  // it runs; so nothing is printed here until it has ended.
  RaxPortableHandleV1 unused;
  uint32_t ran = rax_portable_v1_process_run(process, &request);
  uint32_t again_status = rax_portable_v1_process_run(process, &unused);
  RaxPortablePollV1 poll = {sizeof poll, 1};
  status = rax_portable_v1_process_join(process, &poll);
  printf("\nrun %u\nrun again %u\n", ran, again_status);
  printf("join %u %.*s\n", status, (int)poll.state.length, (const char *)poll.state.data);

  // The record: its size first, then too little room, then the text.
  char text[256];
  RaxPortableBufferV1 buffer = {(uint8_t *)text, 0, 0};
  printf("size %u %d\n", rax_portable_v1_record_read(poll.result, &buffer), buffer.written > 0);
  buffer.capacity = 4;
  printf("small %u\n", rax_portable_v1_record_read(poll.result, &buffer));
  buffer.capacity = sizeof text;
  status = rax_portable_v1_record_read(poll.result, &buffer);
  printf("record %u %.*s\n", status, (int)buffer.written, text);

  // Polling an ended request says the same, with a record of its own.
  RaxPortablePollV1 again = {sizeof again, 1};
  printf("poll %u %.*s\n", rax_portable_v1_poll(request, &again), (int)again.state.length,
         (const char *)again.state.data);
  printf("records differ %d\n", again.result.slot != poll.result.slot);

  // A handle is good until it is released, and then names nothing.
  printf("retain %u\n", rax_portable_v1_retain(poll.result));
  printf("release %u %u %u\n", rax_portable_v1_release(poll.result), rax_portable_v1_release(poll.result),
         rax_portable_v1_release(poll.result));
  printf("read released %u\n", rax_portable_v1_record_read(poll.result, &buffer));
  printf("release others %u %u %u %u %u\n", rax_portable_v1_release(again.result),
         rax_portable_v1_release(request), rax_portable_v1_release(process), rax_portable_v1_release(module),
         rax_portable_v1_release(context));
  printf("use released %u\n", rax_portable_v1_module_verify(context, image, &module));
  // What is not implemented says so.
  printf("symbol %u\n", rax_portable_v1_symbol(module, bytes_of("c"), bytes_of("main"), &process));
  return 0;
}
