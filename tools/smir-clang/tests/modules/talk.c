// A program that needs `words`. Each writes whole lines to standard output
// through its own C library.
#include <stdio.h>

char *describe(int value);
void release(char *text);
void announce(const char *what);
unsigned long measure(const char *text);

int main(void) {
  char *text = describe(42);
  printf("program says %s of %lu\n", text, measure(text));
  fflush(stdout);
  announce("hello");
  fflush(stdout);
  printf("program again\n");
  fflush(stdout);
  announce("goodbye");
  release(text);
  return 3;
}
