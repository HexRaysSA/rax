// A small inventory split over three translation units: the store owns the
// data, the orderings supply comparison functions, and the report combines
// them. The functions of report.c are the test's entry points: each resets
// the store before it reads it.
#ifndef INVENTORY_H
#define INVENTORY_H
#include <stdint.h>

struct item {
  uint32_t code;
  uint32_t quantity;
  uint32_t price;
};

typedef int (*item_order)(const struct item *, const struct item *);

// store.c
extern uint32_t item_count;
extern struct item items[16];
extern const char *const category_names[4];
void store_reset(uint32_t seed);
// The item added to or created, or null when the store is full.
struct item *store_add(uint32_t code, uint32_t quantity, uint32_t price);
const struct item *store_find(uint32_t code);

// order.c
extern const item_order orders[3];
void sort_items(struct item *first, uint32_t count, item_order order);

// Shared by every unit; each gets its own copy.
static inline uint32_t item_value(const struct item *item) { return item->quantity * item->price; }

// report.c
uint32_t total_value(uint32_t seed);
uint32_t sorted_digest(uint32_t seed, uint32_t order);
uint32_t find_quantity(uint32_t seed, uint32_t code);
uint32_t category_digest(uint32_t seed);
uint32_t restock(uint32_t seed, uint32_t rounds);

#endif
