// The smallest program that does something visible.
#include <smir/services.h>

int main(void) {
  static const char text[] = "hello, world\n";
  uint64_t written;
  if (smir_file_write(SMIR_STANDARD_OUTPUT, text, sizeof text - 1, &written) != 0)
    return 1;
  return written == sizeof text - 1 ? 0 : 2;
}
