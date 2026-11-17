#include "order.h"

#include "text.h"

static int alphabetical(const char *left, const char *right) { return text_compare(left, right); }

static int reversed(const char *left, const char *right) { return text_compare(right, left); }

static int by_length(const char *left, const char *right) {
  uint64_t a = text_length(left), b = text_length(right);
  return a != b ? (a > b) - (a < b) : text_compare(left, right);
}

const struct named_order orders[] = {
    {"alphabetical", alphabetical},
    {"reversed", reversed},
    {"length", by_length},
};
const uint32_t order_count = sizeof orders / sizeof orders[0];

line_order find_order(const char *name) {
  for (uint32_t i = 0; i < order_count; i++)
    if (text_compare(orders[i].name, name) == 0)
      return orders[i].order;
  return 0;
}

static uint32_t comparisons;

uint32_t sort_lines(const char **lines, uint32_t count, line_order order) {
  comparisons = 0;
  for (uint32_t i = 1; i < count; i++) {
    const char *line = lines[i];
    uint32_t j = i;
    for (; j > 0; j--) {
      comparisons++;
      if (order(lines[j - 1], line) <= 0)
        break;
      lines[j] = lines[j - 1];
    }
    lines[j] = line;
  }
  return comparisons;
}
