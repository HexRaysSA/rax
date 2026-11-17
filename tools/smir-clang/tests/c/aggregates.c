// Aggregates passed and returned by value, and arithmetic that reports
// overflow.
//
// A structure passed by value is the callee's own copy: what the callee does
// to it is not seen by the caller, and what the caller does afterwards is not
// seen by the callee.
#include <stdint.h>

struct pair {
  int32_t first, second;
};

struct block {
  uint64_t words[4];
};

struct mixed {
  char tag;
  double weight;
  int16_t count;
  uint8_t bytes[5];
};

__attribute__((noinline)) static int64_t take_pair(struct pair value) {
  value.first += 100;
  return (int64_t)value.first * 3 - value.second;
}

__attribute__((noinline)) static uint64_t scramble(struct block value) {
  // Changes its own copy only.
  for (int i = 0; i < 4; i++)
    value.words[i] = value.words[i] * 0x9e3779b97f4a7c15ull + (uint64_t)i;
  return value.words[0] ^ value.words[1] >> 7 ^ value.words[2] << 3 ^ value.words[3];
}

__attribute__((noinline)) static struct pair swap(struct pair value) {
  struct pair result = {value.second, value.first};
  return result;
}

uint64_t pass_small(uint32_t a, uint32_t b) {
  struct pair value = {(int32_t)(a & 0xffff), (int32_t)(b & 0xffff)};
  int64_t taken = take_pair(value);
  // The call did not change the caller's object.
  struct pair swapped = swap(value);
  return (uint64_t)taken * 65536 + (uint64_t)(value.first * 2 + swapped.first * 5 - swapped.second);
}

uint64_t pass_large(uint64_t seed) {
  struct block value;
  for (int i = 0; i < 4; i++)
    value.words[i] = seed = seed * 6364136223846793005ull + 1442695040888963407ull;
  uint64_t first = scramble(value);
  value.words[2] ^= first;
  return first + scramble(value) * 3 + value.words[0];
}

__attribute__((noinline)) static double weigh(struct mixed value, struct pair scale) {
  double total = value.weight * (double)scale.first + (double)value.count / (double)(scale.second | 1);
  for (int i = 0; i < 5; i++)
    total += (double)value.bytes[i] * 0.125;
  return total + (double)value.tag;
}

double pass_mixed(uint32_t seed, double weight) {
  struct mixed value = {(char)(seed & 0x3f), weight, (int16_t)(seed >> 8), {1, 2, 3, 4, 5}};
  value.bytes[seed % 5] = (uint8_t)(seed >> 24);
  struct pair scale = {(int32_t)(seed % 7) - 3, (int32_t)(seed % 11)};
  return weigh(value, scale);
}

// Each activation of a recursive function has its own copy.
__attribute__((noinline)) static uint64_t descend(struct block value, uint32_t depth) {
  if (depth == 0)
    return value.words[0] + value.words[3];
  value.words[depth & 3] += depth;
  uint64_t below = descend(value, depth - 1);
  // The deeper activations changed their copies, not this one.
  return below * 31 + value.words[depth & 3];
}

uint64_t recursive_copies(uint64_t seed, uint32_t depth) {
  struct block value = {{seed, seed >> 8, seed >> 16, seed >> 24}};
  return descend(value, depth % 12);
}

// A structure by value through a function pointer.
typedef int64_t (*pair_function)(struct pair);

static int64_t pair_sum(struct pair value) { return (int64_t)value.first + value.second; }
static int64_t pair_product(struct pair value) { return (int64_t)value.first * value.second; }

__attribute__((noinline)) static int64_t apply(pair_function function, struct pair value) { return function(value); }

int64_t through_pointer(int32_t a, int32_t b, uint32_t which) {
  struct pair value = {a, b};
  static const pair_function functions[3] = {pair_sum, pair_product, take_pair};
  return apply(functions[which % 3], value) + value.first;
}

// A union by value.
union view {
  uint64_t whole;
  uint16_t parts[4];
};

__attribute__((noinline)) static uint32_t fold(union view value) {
  value.parts[1] ^= 0x5a5a;
  return (uint32_t)(value.whole >> 32) ^ (uint32_t)value.whole;
}

uint32_t pass_union(uint64_t bits) {
  union view value = {bits};
  return fold(value) + value.parts[1];
}

// Arithmetic that reports whether the exact result fits.
uint32_t checked_signed(int32_t a, int32_t b) {
  int32_t sum, difference, product;
  uint32_t flags = 0;
  flags |= (uint32_t)__builtin_add_overflow(a, b, &sum) << 0;
  flags |= (uint32_t)__builtin_sub_overflow(a, b, &difference) << 1;
  flags |= (uint32_t)__builtin_mul_overflow(a, b, &product) << 2;
  return flags ^ (uint32_t)sum * 8 ^ (uint32_t)difference * 64 ^ (uint32_t)product * 512;
}

uint32_t checked_unsigned(uint32_t a, uint32_t b) {
  uint32_t sum, difference, product;
  uint32_t flags = 0;
  flags |= (uint32_t)__builtin_add_overflow(a, b, &sum) << 0;
  flags |= (uint32_t)__builtin_sub_overflow(a, b, &difference) << 1;
  flags |= (uint32_t)__builtin_mul_overflow(a, b, &product) << 2;
  return flags ^ sum * 8 ^ difference * 64 ^ product * 512;
}

uint64_t checked_wide(uint64_t a, uint64_t b) {
  uint64_t unsigned_product, unsigned_sum;
  int64_t signed_product, signed_difference;
  uint64_t flags = 0;
  flags |= (uint64_t)__builtin_mul_overflow(a, b, &unsigned_product) << 0;
  flags |= (uint64_t)__builtin_add_overflow(a, b, &unsigned_sum) << 1;
  flags |= (uint64_t)__builtin_mul_overflow((int64_t)a, (int64_t)b, &signed_product) << 2;
  flags |= (uint64_t)__builtin_sub_overflow((int64_t)a, (int64_t)b, &signed_difference) << 3;
  return flags ^ unsigned_product * 16 ^ unsigned_sum * 3 ^ (uint64_t)signed_product * 5 ^ (uint64_t)signed_difference * 7;
}

int32_t checked_narrow(int8_t a, int8_t b) {
  int8_t sum, product;
  int16_t wide;
  int overflowed = __builtin_add_overflow(a, b, &sum) + 2 * __builtin_mul_overflow(a, b, &product) +
                   4 * __builtin_mul_overflow((int16_t)(a * 200), (int16_t)b, &wide);
  return overflowed * 100000 + sum * 300 + product + wide;
}

// A saturating sum built on the overflow flag.
int32_t saturating_total(int32_t start, int32_t step) {
  int32_t total = start;
  for (int i = 0; i < 6; i++)
    if (__builtin_add_overflow(total, step, &total))
      return step < 0 ? INT32_MIN : INT32_MAX;
  return total;
}
