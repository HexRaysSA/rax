#include "inventory.h"

static int by_code(const struct item *a, const struct item *b) { return (a->code > b->code) - (a->code < b->code); }

static int by_value(const struct item *a, const struct item *b) {
  uint32_t left = item_value(a), right = item_value(b);
  return left != right ? (left > right) - (left < right) : by_code(a, b);
}

// A different function from the one of the same name in store.c.
static uint32_t scramble(uint32_t value) { return (value ^ value >> 5) * 31; }

static int by_scramble(const struct item *a, const struct item *b) {
  uint32_t left = scramble(a->code), right = scramble(b->code);
  return left != right ? (left > right) - (left < right) : by_code(a, b);
}

const item_order orders[3] = {by_code, by_value, by_scramble};

void sort_items(struct item *first, uint32_t count, item_order order) {
  for (uint32_t i = 1; i < count; i++) {
    struct item moved = first[i];
    uint32_t j = i;
    for (; j > 0 && order(&first[j - 1], &moved) > 0; j--)
      first[j] = first[j - 1];
    first[j] = moved;
  }
}
