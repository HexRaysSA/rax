// Thread-local variables, in the one thread a function is called on: plain
// and aggregate, initialized and zero, read, written, and reached through a
// pointer. The functions reset what they use, since a native build calls
// them all on one thread.
#include <stdint.h>

static _Thread_local uint32_t counter = 7;
_Thread_local int64_t cleared;

static _Thread_local struct {
  uint8_t tag;
  uint64_t wide;
  uint16_t items[5];
} record = {3, 0x1122334455667788u, {1, 2, 3, 4, 5}};

uint32_t local_counter(uint32_t step, uint32_t rounds) {
  counter = 7;
  for (uint32_t round = 0; round < (rounds & 15); round++)
    counter = counter * 3 + step;
  return counter;
}

__attribute__((noinline)) static void add_through(int64_t *slot, int64_t amount) { *slot += amount; }

int64_t local_through_pointer(int32_t first, int32_t second) {
  cleared = 0;
  add_through(&cleared, first);
  add_through(&cleared, second);
  // The same variable has one address for the thread.
  return cleared + (&cleared == &cleared ? 1000 : 0);
}

uint64_t local_record(uint32_t index, uint16_t value) {
  record.tag = 3;
  record.wide = 0x1122334455667788u;
  for (uint32_t item = 0; item < 5; item++)
    record.items[item] = (uint16_t)(item + 1);
  record.items[index % 5] = value;
  uint64_t sum = record.tag + record.wide;
  for (uint32_t item = 0; item < 5; item++)
    sum = sum * 31 + record.items[item];
  return sum;
}

// A function's own thread-local variable keeps its value between calls.
static uint32_t next_ticket(void) {
  static _Thread_local uint32_t ticket = 100;
  return ticket++;
}

uint32_t local_static(uint32_t calls) {
  uint32_t first = next_ticket(), last = first;
  for (uint32_t call = 0; call < (calls & 7); call++)
    last = next_ticket();
  return last - first;
}
