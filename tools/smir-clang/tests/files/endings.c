// What a program has printed is written when it ends in good order, however
// late it was printed and whether or not a line was finished: by `main`, by
// a function registered with `atexit`, and by a destructor function, which
// runs last.
#include <stdio.h>
#include <stdlib.h>

static FILE *note;

static void registered(void) {
  printf("atexit, ");
  fputs("a note never closed\n", note);
}

__attribute__((destructor)) static void last(void) { printf("destructor"); }

int main(int argc, char **argv) {
  note = fopen("note.txt", "w");
  atexit(registered);
  printf("main, ");
  // With an argument the program ends from inside a function instead.
  if (argc > 1)
    exit(3);
  return 0;
}
