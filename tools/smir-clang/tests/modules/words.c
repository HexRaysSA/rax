// A module with a C library of its own: its memory and its streams are not
// those of the program that needs it.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *describe(int value) {
  char *text = malloc(32);
  snprintf(text, 32, "<%d>", value);
  return text;
}
// What this module allocated, this module frees.
void release(char *text) { free(text); }
void announce(const char *what) { printf("library says %s\n", what); }
unsigned long measure(const char *text) { return strlen(text); }
