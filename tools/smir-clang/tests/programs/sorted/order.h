// Orderings of lines, and a sort that takes one.
#ifndef ORDER_H
#define ORDER_H
#include <stdint.h>

typedef int (*line_order)(const char *, const char *);

struct named_order {
  const char *name;
  line_order order;
};

extern const struct named_order orders[];
extern const uint32_t order_count;

// The ordering called `name`, or null.
line_order find_order(const char *name);

// A stable sort; returns the number of comparisons it made.
uint32_t sort_lines(const char **lines, uint32_t count, line_order order);

#endif
