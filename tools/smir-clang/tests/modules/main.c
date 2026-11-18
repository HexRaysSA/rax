// A program that needs `shapes` and `base`, which `shapes` needs too.
#include <stdio.h>

int scale(int);
long count(void);
int area(int w, int h);
long ticks(void);
long stored_value(void);

int main(int argc, char **argv) {
  printf("%s arguments\n", argc > 1 ? argv[argc - 1] : "no");
  printf("area %d, scale %d\n", area(argc + 4, 2), scale(argc + 4));
  // One counter, in the one `base` there is.
  long first = count();
  printf("counts %ld %ld\n", first, ticks());
  printf("order %ld\n", stored_value());
  return 40 + argc;
}
