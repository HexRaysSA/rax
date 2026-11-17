#include "inventory.h"

uint32_t item_count;
struct item items[16];
const char *const category_names[4] = {"tools", "parts", "paint", "misc"};

// Each unit has its own function of this name.
static uint32_t scramble(uint32_t value) { return value * 2654435761u >> 7; }

void store_reset(uint32_t seed) {
  item_count = 0;
  for (uint32_t i = 0; i < 10; i++) {
    seed = scramble(seed + i);
    store_add(100 + seed % 40, 1 + (seed >> 8) % 9, 5 + (seed >> 16) % 200);
  }
}

struct item *store_add(uint32_t code, uint32_t quantity, uint32_t price) {
  for (uint32_t i = 0; i < item_count; i++)
    if (items[i].code == code) {
      items[i].quantity += quantity;
      return &items[i];
    }
  if (item_count == 16)
    return 0;
  items[item_count] = (struct item){code, quantity, price};
  return &items[item_count++];
}

const struct item *store_find(uint32_t code) {
  for (uint32_t i = 0; i < item_count; i++)
    if (items[i].code == code)
      return &items[i];
  return 0;
}
