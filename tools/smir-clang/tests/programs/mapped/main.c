// mapped [COUNT]: memory mapped from the runtime, used as a growing table.
// The table starts as one mapping and moves to one twice the size whenever
// it is full; the old mapping is unmapped. Then the requests the runtime
// refuses, and a mapping that is made read-only and read.
#include <smir/services.h>

static void say(const char *text) {
  uint64_t length = 0, written;
  while (text[length])
    length++;
  smir_file_write(SMIR_STANDARD_OUTPUT, text, length, &written);
}

static void say_number(const char *label, uint64_t value) {
  char digits[24];
  int at = sizeof digits;
  digits[--at] = 0;
  digits[--at] = '\n';
  do
    digits[--at] = (char)('0' + value % 10);
  while ((value /= 10) != 0);
  say(label);
  say(digits + at);
}

int main(int argc, char **argv) {
  uint64_t count = 5000;
  if (argc > 1) {
    count = 0;
    for (const char *digit = argv[1]; *digit; digit++)
      count = count * 10 + (uint64_t)(*digit - '0');
  }
  uint64_t capacity = 64, moves = 0;
  void *base;
  if (smir_memory_map(capacity * sizeof(uint64_t), 8, SMIR_MAP_READ | SMIR_MAP_WRITE, &base) != 0)
    return 1;
  uint64_t *table = base;
  // Fresh memory is zero.
  uint64_t fresh = 0;
  for (uint64_t index = 0; index < capacity; index++)
    fresh += table[index];
  for (uint64_t index = 0; index < count; index++) {
    if (index == capacity) {
      if (smir_memory_map(2 * capacity * sizeof(uint64_t), 8, SMIR_MAP_READ | SMIR_MAP_WRITE, &base) != 0)
        return 2;
      uint64_t *larger = base;
      for (uint64_t item = 0; item < capacity; item++)
        larger[item] = table[item];
      if (smir_memory_unmap(table, capacity * sizeof(uint64_t)) != 0)
        return 3;
      table = larger;
      capacity *= 2;
      moves++;
    }
    table[index] = index * index + 1;
  }
  uint64_t sum = 0;
  for (uint64_t index = 0; index < count; index++)
    sum = sum * 31 + table[index];
  say_number("fresh ", fresh);
  say_number("capacity ", capacity);
  say_number("moves ", moves);
  say_number("sum ", sum);

  // Read-only from here on; what was written is still there.
  uint64_t bytes = capacity * sizeof(uint64_t);
  say_number("protect ", smir_memory_protect(table, bytes, SMIR_MAP_READ));
  say_number("first ", table[0]);

  // What the runtime refuses: part of a mapping, a size that is not the
  // mapping's, a second unmapping, nothing to map, a strange alignment.
  say_number("unmap part ", smir_memory_unmap(table + 1, bytes - 8) != 0);
  say_number("unmap wrong size ", smir_memory_unmap(table, bytes / 2) != 0);
  say_number("unmap ", smir_memory_unmap(table, bytes));
  say_number("unmap again ", smir_memory_unmap(table, bytes) != 0);
  say_number("map nothing ", smir_memory_map(0, 8, SMIR_MAP_READ, &base) != 0);
  say_number("null base ", base == 0);
  say_number("map misaligned ", smir_memory_map(64, 24, SMIR_MAP_READ, &base) != 0);
  return 0;
}
