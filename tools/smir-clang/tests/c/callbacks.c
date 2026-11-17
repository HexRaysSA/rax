// Function pointers: passed as arguments, kept in constant tables and in
// structures, stored to and loaded from memory, returned, selected, compared
// and called.
#include <stdint.h>

typedef int (*comparison)(uint32_t, uint32_t);

static int ascending(uint32_t a, uint32_t b) { return a < b ? -1 : a > b; }
static int descending(uint32_t a, uint32_t b) { return ascending(b, a); }
static int by_low_byte(uint32_t a, uint32_t b) { return ascending(a & 0xff, b & 0xff); }
static int by_bit_count(uint32_t a, uint32_t b) {
  return ascending((uint32_t)__builtin_popcount(a), (uint32_t)__builtin_popcount(b));
}

// The noinline attributes keep the calls indirect at every level; without
// them the optimizer would specialize the sort for each comparison.
__attribute__((noinline)) static void insertion_sort(uint32_t *items, uint32_t count, comparison order) {
  for (uint32_t i = 1; i < count; i++) {
    uint32_t item = items[i], j = i;
    for (; j > 0 && order(items[j - 1], item) > 0; j--)
      items[j] = items[j - 1];
    items[j] = item;
  }
}

static uint32_t fill(uint32_t *items, uint32_t count, uint32_t seed) {
  for (uint32_t i = 0; i < count; i++) {
    seed = seed * 1664525u + 1013904223u;
    items[i] = seed >> 8;
  }
  return seed;
}

static uint32_t digest(const uint32_t *items, uint32_t count) {
  uint32_t hash = 2166136261u;
  for (uint32_t i = 0; i < count; i++)
    hash = (hash ^ items[i]) * 16777619u;
  return hash;
}

static const comparison orders[4] = {ascending, descending, by_low_byte, by_bit_count};

uint32_t sort_with(uint32_t seed, uint32_t which) {
  uint32_t items[12];
  fill(items, 12, seed);
  insertion_sort(items, 12, orders[which & 3]);
  return digest(items, 12);
}

// A generic sort over untyped elements, in the shape of qsort.
typedef int (*untyped_comparison)(const void *, const void *);

static int compare_u16(const void *left, const void *right) {
  uint16_t a = *(const uint16_t *)left, b = *(const uint16_t *)right;
  return (a > b) - (a < b);
}

static int compare_pair(const void *left, const void *right) {
  const uint8_t *a = left, *b = right;
  return a[1] != b[1] ? (int)a[1] - (int)b[1] : (int)a[0] - (int)b[0];
}

__attribute__((noinline)) static void sort_bytes(void *base, uint32_t count, uint32_t size, untyped_comparison order) {
  uint8_t *bytes = base;
  for (uint32_t i = 1; i < count; i++)
    for (uint32_t j = i; j > 0 && order(bytes + (j - 1) * size, bytes + j * size) > 0; j--)
      for (uint32_t k = 0; k < size; k++) {
        uint8_t swap = bytes[(j - 1) * size + k];
        bytes[(j - 1) * size + k] = bytes[j * size + k];
        bytes[j * size + k] = swap;
      }
}

uint32_t generic_sort(uint32_t seed, uint32_t pairs) {
  uint16_t items[10];
  for (uint32_t i = 0; i < 10; i++) {
    seed = seed * 1103515245u + 12345u;
    items[i] = (uint16_t)(seed >> 12);
  }
  sort_bytes(items, 10, 2, pairs & 1 ? compare_pair : compare_u16);
  uint32_t hash = 0;
  for (uint32_t i = 0; i < 10; i++)
    hash = hash * 65599u + items[i];
  return hash;
}

// A callback with a context pointer.
typedef void (*visitor)(void *context, uint32_t value);

struct statistics {
  uint32_t count;
  uint32_t sum;
  uint32_t largest;
};

static void gather(void *context, uint32_t value) {
  struct statistics *statistics = context;
  statistics->count++;
  statistics->sum += value;
  if (value > statistics->largest)
    statistics->largest = value;
}

static void mix(void *context, uint32_t value) {
  uint32_t *state = context;
  *state = (*state ^ value) * 0x9e3779b1u;
}

__attribute__((noinline)) static void each_divisor(uint32_t number, visitor visit, void *context) {
  for (uint32_t divisor = 1; divisor <= number; divisor++)
    if (number % divisor == 0)
      visit(context, divisor);
}

uint32_t divisor_statistics(uint32_t number) {
  struct statistics statistics = {0, 0, 0};
  uint32_t state = 1;
  number = number % 360 + 1;
  each_divisor(number, gather, &statistics);
  each_divisor(number, mix, &state);
  return statistics.count + statistics.sum * 16 + statistics.largest * 4096 + state;
}

// A small stack machine whose operations are a table of handlers.
struct machine {
  uint32_t stack[8];
  uint32_t depth;
};

typedef void (*handler)(struct machine *, uint32_t operand);

static void push(struct machine *machine, uint32_t operand) { machine->stack[machine->depth++ & 7] = operand; }
static uint32_t pop(struct machine *machine) { return machine->stack[--machine->depth & 7]; }
static void op_add(struct machine *machine, uint32_t operand) {
  uint32_t top = pop(machine);
  push(machine, top + pop(machine) + operand);
}
static void op_mul(struct machine *machine, uint32_t operand) {
  uint32_t top = pop(machine);
  push(machine, top * (pop(machine) | 1) + operand);
}
static void op_dup(struct machine *machine, uint32_t operand) {
  uint32_t top = pop(machine);
  push(machine, top);
  push(machine, top ^ operand);
}
static void op_rot(struct machine *machine, uint32_t operand) {
  uint32_t top = pop(machine);
  push(machine, top << (operand & 31) | top >> (-operand & 31));
}

struct instruction {
  handler run;
  uint32_t operand;
};

static const struct instruction program[] = {
    {push, 3}, {push, 5}, {op_add, 1}, {op_dup, 0xff}, {op_mul, 7}, {op_rot, 5}, {op_dup, 9}, {op_add, 0},
};

uint32_t run_program(uint32_t seed, uint32_t length) {
  struct machine machine = {{seed, seed >> 3, seed >> 7, 1, 2, 3, 4, 5}, 2};
  length = length % (sizeof program / sizeof program[0] + 1);
  for (uint32_t i = 0; i < length; i++)
    program[i].run(&machine, program[i].operand + i);
  return pop(&machine) + machine.depth;
}

// Function pointers as values: chosen, stored, loaded, returned and compared.
typedef uint32_t (*unary)(uint32_t);

static uint32_t increment(uint32_t x) { return x + 1; }
static uint32_t twice(uint32_t x) { return x * 2; }
static uint32_t square(uint32_t x) { return x * x; }
static uint32_t negate(uint32_t x) { return 0u - x; }

__attribute__((noinline)) static unary choose(uint32_t selector) {
  switch (selector % 5) {
  case 0:
    return increment;
  case 1:
    return twice;
  case 2:
    return square;
  case 3:
    return negate;
  default:
    return 0;
  }
}

uint32_t apply_chosen(uint32_t selector, uint32_t value) {
  unary function = choose(selector);
  // No function is chosen for one selector in five.
  if (!function)
    return value ^ 0xdeadbeef;
  return function(function(value));
}

uint32_t compare_pointers(uint32_t left, uint32_t right) {
  unary a = choose(left), b = choose(right);
  uint32_t result = a == b;
  result |= (uint32_t)(a != increment) << 1;
  result |= (uint32_t)(b == 0) << 2;
  result |= (uint32_t)(a == (left & 1 ? twice : square)) << 3;
  return result;
}

static unary slots[4];

uint32_t stored_pointers(uint32_t order, uint32_t value) {
  // Function pointers written to and read back from memory.
  for (uint32_t i = 0; i < 4; i++)
    slots[i] = choose(order + i * 3);
  unary pipeline[3] = {slots[order & 3], slots[order >> 2 & 3], slots[order >> 4 & 3]};
  for (uint32_t i = 0; i < 3; i++)
    if (pipeline[i])
      value = pipeline[i](value) + i;
  return value;
}

// A function that takes and returns function pointers.
__attribute__((noinline)) static unary either(unary first, unary second, uint32_t which) {
  return which & 1 ? first : second;
}

static uint32_t compose(unary outer, unary inner, uint32_t value) { return outer(inner(value)); }

uint32_t higher_order(uint32_t which, uint32_t value) {
  unary f = either(increment, twice, which);
  unary g = either(square, negate, which >> 1);
  return compose(f, g, value) ^ compose(g, f, value);
}

// Mutual recursion through a table.
static uint32_t even_step(uint32_t n, uint32_t depth);
static uint32_t odd_step(uint32_t n, uint32_t depth);

static uint32_t (*const steps[2])(uint32_t, uint32_t) = {even_step, odd_step};

static uint32_t even_step(uint32_t n, uint32_t depth) { return n <= 1 ? depth : steps[(n / 2) & 1](n / 2, depth + 1); }
static uint32_t odd_step(uint32_t n, uint32_t depth) { return n <= 1 ? depth : steps[(3 * n + 1) & 1](3 * n + 1, depth + 1); }

uint32_t collatz_table(uint32_t start) {
  start = start % 1000 + 1;
  return steps[start & 1](start, 0);
}
