// A host that has functions for its programs to call, written against the
// contract's header and linked with the runtime's static library.
//
//     host PROGRAM.smo [lacking]
//
// It registers `app:add`, `app:tick` and `app.math:scale` with the
// descriptors `descriptors.h` has for them, which the test writes from what
// the compiler wrote beside the program, and runs the program. `add` and
// `scale` answer before they return. `tick` leaves its call pending, and a
// thread of the host's own answers it. With `lacking`, `tick` is not
// registered, and the program is no program for this host.
#include "rax_portable_extensions_v1.h"

#include "descriptors.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static RaxPortableBytesV1 bytes_of(const void *data, uint64_t length) {
  RaxPortableBytesV1 bytes = {data, length};
  return bytes;
}

// The bits of a value of up to 64 bits.
static uint64_t bits_of(RaxPortableHandleV1 value) {
  uint64_t bits = 0;
  RaxPortableBufferV1 buffer = {(uint8_t *)&bits, sizeof bits, 0};
  if (rax_portable_v1_value_read_bits(value, &buffer) != 0)
    abort();
  return bits;
}

// Answer a call with one result of `width` bytes.
static RaxPortableStatusV1 answer(RaxPortableHandleV1 call, uint64_t result, uint64_t width,
                                  RaxPortablePollV1 *poll) {
  RaxPortableHandleV1 value;
  RaxPortableStatusV1 status = rax_portable_v1_call_result_bits(call, 0, bytes_of(&result, width), &value);
  if (status != 0)
    return status;
  status = rax_portable_v1_call_return(call, &value, 1, poll);
  rax_portable_v1_release(value);
  return status;
}

static RaxPortableStatusV1 add(void *user, RaxPortableHandleV1 call, const RaxPortableHandleV1 *arguments,
                               uint64_t count, RaxPortablePollV1 *result) {
  (void)user;
  if (count != 2)
    return 22;
  uint32_t sum = (uint32_t)bits_of(arguments[0]) + (uint32_t)bits_of(arguments[1]);
  return answer(call, sum, 4, result);
}

static RaxPortableStatusV1 scale(void *user, RaxPortableHandleV1 call, const RaxPortableHandleV1 *arguments,
                                 uint64_t count, RaxPortablePollV1 *result) {
  (void)user;
  if (count != 2)
    return 22;
  uint64_t bits = bits_of(arguments[0]);
  double number;
  memcpy(&number, &bits, sizeof number);
  number *= (double)(int64_t)bits_of(arguments[1]);
  memcpy(&bits, &number, sizeof bits);
  return answer(call, bits, 8, result);
}

// The call of `tick` that waits for its answer, and the thread that gives it.
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t asked = PTHREAD_COND_INITIALIZER;
static RaxPortableHandleV1 waiting;
static int has_waiting, finished;

static RaxPortableStatusV1 tick(void *user, RaxPortableHandleV1 call, const RaxPortableHandleV1 *arguments,
                                uint64_t count, RaxPortablePollV1 *result) {
  (void)user, (void)arguments;
  if (count != 0)
    return 22;
  pthread_mutex_lock(&lock);
  waiting = call;
  has_waiting = 1;
  pthread_cond_signal(&asked);
  pthread_mutex_unlock(&lock);
  result->state = bytes_of("pending", 7);
  return 0;
}

static void *answering(void *unused) {
  (void)unused;
  uint64_t ticks = 0;
  for (;;) {
    pthread_mutex_lock(&lock);
    while (!has_waiting && !finished)
      pthread_cond_wait(&asked, &lock);
    RaxPortableHandleV1 call = waiting;
    int more = has_waiting;
    has_waiting = 0;
    pthread_mutex_unlock(&lock);
    if (!more)
      return 0;
    RaxPortablePollV1 completion = {sizeof completion, 1};
    if (answer(call, ++ticks, 8, &completion) != 0 || rax_portable_v1_host_complete(call, &completion) != 0)
      abort();
  }
}

static int released;
static void release(void *user) {
  (void)user;
  released++;
}

int main(int argc, char **argv) {
  if (argc < 2)
    return 2;
  FILE *file = fopen(argv[1], "rb");
  if (!file)
    return 2;
  static uint8_t image[64 << 20];
  uint64_t size = fread(image, 1, sizeof image, file);
  fclose(file);

  RaxPortableHostImportV1 functions[] = {
      {sizeof functions[0], 1, bytes_of("app:add", 7), bytes_of(add_descriptor, sizeof add_descriptor), add, release, 0},
      {sizeof functions[0], 1, bytes_of("", 0), bytes_of(scale_descriptor, sizeof scale_descriptor), scale, release, 0},
      {sizeof functions[0], 1, bytes_of("", 0), bytes_of(tick_descriptor, sizeof tick_descriptor), tick, release, 0},
  };
  // What a program with a C library may need of the runtime's services; the
  // capability to call the host's functions comes with registering any.
  RaxPortableBytesV1 grants[] = {bytes_of("clock", 5),   bytes_of("file", 4), bytes_of("memory", 6),
                                 bytes_of("process", 7), bytes_of("sync", 4), bytes_of("thread", 6)};
  RaxPortableConfigV1 config = {sizeof config, 1};
  config.capabilities = grants;
  config.capability_count = sizeof grants / sizeof grants[0];
  config.imports = functions;
  config.import_count = argc > 2 ? 2 : 3;
  RaxPortableHandleV1 context, module, process, request;
  if (rax_portable_v1_context_create(&config, &context) != 0)
    return 3;
  if (rax_portable_v1_module_verify(context, bytes_of(image, size), &module) != 0)
    return 4;
  RaxPortableStatusV1 status = rax_portable_v1_process_create(context, module, bytes_of("", 0), &process);
  if (status != 0) {
    printf("no program for this host: %u\n", status);
    rax_portable_v1_release(module);
    rax_portable_v1_release(context);
    printf("released %d\n", released);
    return 5;
  }
  pthread_t thread;
  pthread_create(&thread, 0, answering, 0);
  if (rax_portable_v1_process_run(process, &request) != 0)
    return 6;
  RaxPortablePollV1 ended = {sizeof ended, 1};
  if (rax_portable_v1_process_join(process, &ended) != 0)
    return 7;
  char record[512] = {0};
  RaxPortableBufferV1 buffer = {(uint8_t *)record, sizeof record - 1, 0};
  rax_portable_v1_record_read(ended.result, &buffer);
  fflush(stdout);
  printf("%s\n", record);

  pthread_mutex_lock(&lock);
  finished = 1;
  pthread_cond_signal(&asked);
  pthread_mutex_unlock(&lock);
  pthread_join(thread, 0);
  rax_portable_v1_release(ended.result);
  rax_portable_v1_release(request);
  rax_portable_v1_release(process);
  rax_portable_v1_release(module);
  printf("released %d\n", released);
  rax_portable_v1_release(context);
  // The host is told once of each function, when nothing uses it any more.
  printf("released %d\n", released);
  return 0;
}
