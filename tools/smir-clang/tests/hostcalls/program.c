// A program that calls functions of its host: the application's own, which
// the host registers with the runtime. Each is declared with the link name
// `host:NAMESPACE:NAME@VERSION`, and takes and returns integers and floats.
#include <stdio.h>

int add(int, int) __asm__("host:app:add@1");
long long tick(void) __asm__("host:app:tick@1");
double scale(double, long long) __asm__("host:app.math:scale@3");

int main(int argc, char **argv) {
  (void)argv;
  printf("add %d\n", add(2, 3));
  // The host counts; what it keeps between calls, it keeps.
  long long first = tick();
  printf("ticks %lld %lld\n", first, tick());
  printf("scale %g\n", scale(1.5, 4));
  return add(40, argc);
}
