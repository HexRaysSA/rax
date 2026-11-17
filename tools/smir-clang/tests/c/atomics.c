// Atomic and volatile objects, on one thread: every ordering, each
// read-modify-write, and compare-and-exchange that succeeds and that fails.
#include <stdatomic.h>
#include <stdint.h>

uint32_t counter_updates(uint32_t start, uint32_t step) {
  atomic_uint counter = start;
  uint32_t seen = 0;
  seen ^= atomic_fetch_add(&counter, step);
  seen ^= atomic_fetch_sub_explicit(&counter, 3, memory_order_relaxed) << 1;
  seen ^= atomic_fetch_or_explicit(&counter, step >> 3, memory_order_acquire) << 2;
  seen ^= atomic_fetch_and_explicit(&counter, ~step, memory_order_release) << 3;
  seen ^= atomic_fetch_xor_explicit(&counter, 0x5a5a5a5a, memory_order_acq_rel) << 4;
  seen ^= atomic_exchange(&counter, seen) << 5;
  counter += step;
  counter ^= start >> 1;
  return seen + atomic_load_explicit(&counter, memory_order_relaxed) * 3;
}

uint64_t exchanges(uint64_t value, uint64_t guess) {
  _Atomic uint64_t cell = value;
  uint64_t expected = guess;
  // Succeeds only when the guess is right; on failure the guess is replaced
  // by what was found.
  _Bool first = atomic_compare_exchange_strong(&cell, &expected, value + 1);
  uint64_t result = (uint64_t)first + expected * 2;
  // Now the expectation is right, so a retry loop ends at once.
  expected = atomic_load(&cell);
  while (!atomic_compare_exchange_weak_explicit(&cell, &expected, expected * 3 + 1, memory_order_seq_cst,
                                                memory_order_relaxed))
    ;
  return result ^ atomic_load(&cell) << 1;
}

static _Atomic int32_t shared_total;
static atomic_flag busy = ATOMIC_FLAG_INIT;

int32_t shared_state(int32_t a, int32_t b) {
  atomic_store(&shared_total, a);
  atomic_flag_clear(&busy);
  int32_t result = atomic_flag_test_and_set(&busy);
  result += atomic_flag_test_and_set(&busy) * 2;
  atomic_fetch_add(&shared_total, b & 0xffff);
  shared_total -= 7;
  atomic_thread_fence(memory_order_seq_cst);
  // Atomic arithmetic wraps; the combination must not overflow either.
  return (int32_t)((uint32_t)result + (uint32_t)atomic_load(&shared_total) * 4u);
}

// Each read of a volatile object is performed, and each write.
uint32_t volatile_accesses(uint32_t value) {
  volatile uint32_t cell = value;
  uint32_t sum = 0;
  for (int i = 0; i < 5; i++) {
    cell = cell * 3 + (uint32_t)i;
    sum += cell;
  }
  volatile uint8_t bytes[4] = {1, 2, 3, 4};
  bytes[value & 3] = (uint8_t)value;
  return sum ^ (uint32_t)(bytes[0] + bytes[1] * 3 + bytes[2] * 5 + bytes[3] * 7);
}

// An atomic pointer.
static uint32_t slots[4] = {11, 22, 33, 44};

uint32_t pointer_exchange(uint32_t first, uint32_t second) {
  uint32_t *_Atomic current = &slots[first & 3];
  uint32_t *previous = atomic_exchange(&current, &slots[second & 3]);
  uint32_t *expected = &slots[first & 3];
  _Bool swapped = atomic_compare_exchange_strong(&current, &expected, &slots[0]);
  return *previous + *atomic_load(&current) * 100 + *expected * 10000 + (uint32_t)swapped;
}
