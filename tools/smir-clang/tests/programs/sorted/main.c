// sorted ORDER: read lines from standard input and print them sorted and
// numbered. The exit status is the number of lines; a usage error is
// reported on standard error with status 200.
#include "order.h"
#include "text.h"

#include <smir/services.h>

static char input[2048];
static const char *lines[64];

static uint32_t split(char *text, uint64_t length) {
  uint32_t count = 0;
  char *start = text;
  for (uint64_t i = 0; i < length && count < 64; i++)
    if (text[i] == '\n') {
      text[i] = 0;
      lines[count++] = start;
      start = text + i + 1;
    }
  // A last line that does not end with a newline.
  if (start < text + length && count < 64)
    lines[count++] = start;
  return count;
}

static int usage(const char *problem, const char *detail) {
  put_text(SMIR_STANDARD_ERROR, "sorted: ");
  put_text(SMIR_STANDARD_ERROR, problem);
  if (detail) {
    put_text(SMIR_STANDARD_ERROR, ": ");
    put_text(SMIR_STANDARD_ERROR, detail);
  }
  put_text(SMIR_STANDARD_ERROR, "\norders:");
  for (uint32_t i = 0; i < order_count; i++) {
    put_text(SMIR_STANDARD_ERROR, " ");
    put_text(SMIR_STANDARD_ERROR, orders[i].name);
  }
  put_text(SMIR_STANDARD_ERROR, "\n");
  return 200;
}

int main(int argc, char **argv) {
  if (argc != 2)
    return usage("expected one argument", 0);
  line_order order = find_order(argv[1]);
  if (!order)
    return usage("unknown order", argv[1]);
  // The buffer keeps one byte for the terminator of an unfinished last line.
  uint64_t length = read_all(input, sizeof input - 1);
  input[length] = 0;
  uint32_t count = split(input, length);
  uint32_t comparisons = sort_lines(lines, count, order);
  for (uint32_t i = 0; i < count; i++) {
    put_number(SMIR_STANDARD_OUTPUT, i + 1);
    put_text(SMIR_STANDARD_OUTPUT, ": ");
    put_text(SMIR_STANDARD_OUTPUT, lines[i]);
    put_text(SMIR_STANDARD_OUTPUT, "\n");
  }
  put_number(SMIR_STANDARD_ERROR, comparisons);
  put_text(SMIR_STANDARD_ERROR, " comparisons\n");
  return (int)count;
}
