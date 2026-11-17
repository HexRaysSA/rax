#include "inventory.h"

uint32_t total_value(uint32_t seed) {
  store_reset(seed);
  uint32_t total = 0;
  for (uint32_t i = 0; i < item_count; i++)
    total += item_value(&items[i]);
  return total + item_count * 1000003u;
}

uint32_t sorted_digest(uint32_t seed, uint32_t order) {
  store_reset(seed);
  sort_items(items, item_count, orders[order % 3]);
  uint32_t digest = order % 3;
  for (uint32_t i = 0; i < item_count; i++)
    digest = digest * 131 + items[i].code + items[i].quantity * 7;
  return digest;
}

uint32_t find_quantity(uint32_t seed, uint32_t code) {
  store_reset(seed);
  const struct item *found = store_find(100 + code % 40);
  return found ? found->quantity * 256 + (uint32_t)(found - items) : 0xffffffffu;
}

uint32_t category_digest(uint32_t seed) {
  store_reset(seed);
  uint32_t digest = 0;
  for (uint32_t i = 0; i < item_count; i++)
    for (const char *name = category_names[items[i].code & 3]; *name; name++)
      digest = digest * 33 + (uint8_t)*name;
  return digest;
}

// A local comparison passed to the sort of another unit.
static int by_quantity(const struct item *a, const struct item *b) {
  return a->quantity != b->quantity ? (a->quantity > b->quantity) - (a->quantity < b->quantity)
                                    : (a->code > b->code) - (a->code < b->code);
}

uint32_t restock(uint32_t seed, uint32_t rounds) {
  store_reset(seed);
  for (uint32_t round = 0; round < rounds % 8; round++) {
    sort_items(items, item_count, by_quantity);
    // The scarcest item is first.
    store_add(items[0].code, round + 2, 0);
    struct item *added = store_add(200 + round, 1, seed % 50 + round);
    if (added)
      added->price += (uint32_t)(added - items);
  }
  uint32_t digest = item_count;
  for (uint32_t i = 0; i < item_count; i++)
    digest = digest * 31 + item_value(&items[i]) + items[i].code;
  return digest;
}
