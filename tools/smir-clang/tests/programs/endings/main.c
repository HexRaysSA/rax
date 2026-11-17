// endings HOW: the ways a program can end. Each writes a line first, so the
// test also sees that output written before the end is not lost.
#include <smir/services.h>

static void say(uint64_t stream, const char *text) {
  uint64_t length = 0, written;
  while (text[length])
    length++;
  smir_file_write(stream, text, length, &written);
}

static int depth(int levels, int status) {
  // The exit happens several calls down.
  if (levels == 0) {
    say(SMIR_STANDARD_OUTPUT, "exiting from a nested call\n");
    smir_process_exit(status, SMIR_EXIT_CLEAN);
  }
  return depth(levels - 1, status) + 1;
}

int main(int argc, char **argv) {
  if (argc < 2) {
    say(SMIR_STANDARD_OUTPUT, "returning seven\n");
    return 7;
  }
  switch (argv[1][0]) {
  case 'e':
    return depth(5, 42);
  case 'q':
    say(SMIR_STANDARD_OUTPUT, "quick exit\n");
    smir_process_exit(3, SMIR_EXIT_QUICK);
  case 'i':
    say(SMIR_STANDARD_ERROR, "immediate exit\n");
    smir_process_exit(0, SMIR_EXIT_IMMEDIATE);
  case 'w':
    // Only the low eight bits of a status are observable.
    say(SMIR_STANDARD_OUTPUT, "status 300\n");
    return 300;
  case 'n':
    say(SMIR_STANDARD_OUTPUT, "negative status\n");
    smir_process_exit(-2, SMIR_EXIT_CLEAN);
  case 'a':
    say(SMIR_STANDARD_ERROR, "aborting\n");
    smir_process_abort();
  case 'b': {
    // A handle that is not open: the write fails with a status.
    uint64_t written = 99;
    uint32_t status = smir_file_write(9, "lost", 4, &written);
    say(SMIR_STANDARD_OUTPUT, status != 0 && written == 0 ? "bad handle refused\n" : "bad handle accepted\n");
    return status != 0;
  }
  default:
    say(SMIR_STANDARD_ERROR, "unknown ending\n");
    return 1;
  }
}
