// Control flow: switches, early exits, short-circuit evaluation and a state
// machine driven by the bits of the argument.
#include <stdint.h>

int32_t classify(int32_t x) {
  switch (x) {
  case 1: return 10;
  case 2: return 20;
  case 7: return 70;
  case 1000: return -5;
  case -3: return 33;
  default: return x < 0 ? -1 : 0;
  }
}

uint32_t dense(uint32_t x) {
  switch (x % 12) {
  case 0: return 3;
  case 1: return 1;
  case 2: return 4;
  case 3: return 1;
  case 4: return 5;
  case 5: return 9;
  case 6: return 2;
  case 7: return 6;
  case 8: return 5;
  case 9: return 3;
  default: return x % 12 + 100;
  }
}

uint32_t machine(uint32_t input) {
  uint32_t state = 0, output = 0;
  for (int i = 0; i < 32; i++) {
    uint32_t bit = input >> i & 1;
    switch (state) {
    case 0: state = bit ? 1 : 0; break;
    case 1: state = bit ? 2 : 0; output += 1; break;
    case 2: state = bit ? 2 : 3; output += 3; break;
    default: state = bit ? 1 : 0; output ^= 0x55; break;
    }
  }
  return output * 4 + state;
}

// Cases written out of order, with negative values, and sparse enough that
// the compiler keeps a switch instead of a table.
int32_t unordered(int32_t x) {
  switch (x) {
  case 900: return 1;
  case 3: return 2;
  case -1: return 3;
  case 40000: return 4;
  case -70000: return 5;
  case 0: return 6;
  case 17: return 7;
  default: return x & 1 ? -2 : -3;
  }
}

int32_t first_set(uint64_t x) {
  for (int32_t i = 0; i < 64; i++)
    if (x >> i & 1)
      return i;
  return -1;
}

uint32_t short_circuit(uint32_t a, uint32_t b) {
  uint32_t result = 0;
  if (a > 10 && b % (a - 10) == 3)
    result |= 1;
  if (a == 0 || b / a > 2)
    result |= 2;
  if (!(a & 1) && !(b & 1))
    result |= 4;
  return result;
}

uint32_t nested_break(uint32_t limit) {
  uint32_t found = 0;
  limit &= 63;
  for (uint32_t i = 1; i < 16; i++) {
    for (uint32_t j = 1; j < 16; j++) {
      if (i * j > limit)
        break;
      if (i * j == limit) {
        found = i * 16 + j;
        goto done;
      }
    }
  }
done:
  return found;
}

int32_t sign_chain(int32_t x) {
  return x > 100 ? 3 : x > 0 ? 2 : x == 0 ? 1 : x > -100 ? -1 : -2;
}
