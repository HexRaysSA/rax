// Global data: constant tables, string literals, mutable and zero-initialized
// globals, globals that hold the addresses of other globals, and the bulk
// copies and fills the compiler emits for aggregate initializers and
// assignments.
//
// Each test case runs in a fresh machine, while the native reference calls
// every case in one process. A function may therefore modify global state,
// but must first reset whatever state it reads.
#include <stdint.h>

static const uint32_t primes[10] = {2, 3, 5, 7, 11, 13, 17, 19, 23, 29};

static const uint8_t grid[3][4] = {{1, 2, 3, 4}, {10, 20, 30, 40}, {100, 101, 102, 103}};

uint32_t prime_table(uint32_t index) { return primes[index % 10] * 3 + primes[(index >> 4) % 10]; }

uint32_t grid_lookup(uint32_t row, uint32_t column) { return grid[row % 3][column & 3] + grid[column % 3][row & 3] * 256u; }

static const char *const words[5] = {"", "a", "portable", "intermediate", "representation"};

static uint32_t string_length(const char *text) {
  uint32_t length = 0;
  while (text[length])
    length++;
  return length;
}

static uint32_t string_hash(const char *text) {
  uint32_t hash = 5381;
  for (; *text; text++)
    hash = hash * 33 + (uint8_t)*text;
  return hash;
}

uint32_t word_length(uint32_t index) { return string_length(words[index % 5]); }

uint32_t word_hash(uint32_t index) { return string_hash(words[index % 5]) ^ string_hash("literal"); }

int32_t word_order(uint32_t left, uint32_t right) {
  const char *a = words[left % 5], *b = words[right % 5];
  while (*a && *a == *b) {
    a++;
    b++;
  }
  return (int32_t)(uint8_t)*a - (int32_t)(uint8_t)*b;
}

uint32_t local_string(uint32_t shift) {
  // An array initialized from a literal is copied from constant data.
  char text[] = "caesar cipher";
  for (uint32_t i = 0; text[i]; i++)
    if (text[i] >= 'a' && text[i] <= 'z')
      text[i] = (char)('a' + (text[i] - 'a' + shift % 26) % 26);
  return string_hash(text);
}

static uint64_t total;
static uint32_t histogram[8];

static void record(uint32_t value) {
  total += value;
  histogram[value & 7]++;
}

uint64_t accumulate(uint32_t seed) {
  total = 0;
  for (int i = 0; i < 8; i++)
    histogram[i] = 0;
  for (int i = 0; i < 20; i++) {
    seed = seed * 1103515245u + 12345u;
    record(seed >> 16 & 0xff);
  }
  uint64_t shape = 0;
  for (int i = 0; i < 8; i++)
    shape = shape * 21 + histogram[i];
  return total * 1000003u + shape;
}

struct range {
  const char *name;
  const uint32_t *first;
  uint32_t count;
};

// Each entry holds the addresses of a string and of a place inside a table.
static const struct range ranges[3] = {
    {"low", &primes[0], 3},
    {"middle", &primes[3], 4},
    {"high", &primes[7], 3},
};

static const struct range *const default_range = &ranges[1];

uint32_t range_sum(uint32_t which) {
  const struct range *range = which % 4 == 3 ? default_range : &ranges[which % 4];
  uint32_t sum = string_length(range->name);
  for (uint32_t i = 0; i < range->count; i++)
    sum = sum * 31 + range->first[i];
  return sum;
}

struct record {
  uint8_t tag;
  uint32_t value;
  uint64_t stamp;
  uint16_t extra[3];
};

static const struct record seed_record = {7, 1000, 0x1122334455667788u, {1, 2, 3}};

static struct record make_record(uint32_t value) {
  // Returned through a hidden result pointer.
  struct record result = seed_record;
  result.value += value;
  result.extra[value % 3] = (uint16_t)value;
  return result;
}

uint64_t structure_copy(uint32_t value) {
  struct record first = make_record(value);
  struct record second = first;
  second.tag ^= 0x55;
  first = second;
  return first.tag + first.value * 3u + first.stamp + first.extra[0] + first.extra[1] * 5u + first.extra[2] * 7u;
}

uint32_t zero_initialized(uint32_t value) {
  uint32_t slots[10] = {0};
  uint16_t partial[6] = {9, 8, 7};
  slots[value % 10] = value;
  partial[3 + value % 3] = (uint16_t)value;
  uint32_t sum = 0;
  for (int i = 0; i < 10; i++)
    sum = sum * 3 + slots[i];
  for (int i = 0; i < 6; i++)
    sum = sum * 5 + partial[i];
  return sum;
}

uint32_t builtin_bulk(uint32_t value, uint32_t count) {
  uint8_t source[16], target[24];
  for (int i = 0; i < 16; i++)
    source[i] = (uint8_t)(value >> (i & 3) * 8) + (uint8_t)i;
  __builtin_memset(target, (int)(value >> 24), sizeof target);
  count %= 17;
  __builtin_memcpy(target + 4, source, count);
  // Overlapping ranges need memmove.
  __builtin_memmove(target + 6, target + 4, 12);
  uint32_t hash = count;
  for (int i = 0; i < 24; i++)
    hash = hash * 131 + target[i];
  return hash;
}

union word {
  uint32_t whole;
  uint8_t bytes[4];
  uint16_t halves[2];
};

uint32_t union_views(uint32_t value) {
  union word word;
  word.whole = value;
  word.bytes[1] ^= 0xff;
  word.halves[1] += 1;
  return word.whole;
}

uint32_t static_local(uint32_t value) {
  static uint32_t memo[4];
  for (int i = 0; i < 4; i++)
    memo[i] = 0;
  for (uint32_t i = 0; i < 12; i++)
    memo[(value + i) & 3] += i * value;
  return memo[0] ^ memo[1] * 3 ^ memo[2] * 5 ^ memo[3] * 7;
}
