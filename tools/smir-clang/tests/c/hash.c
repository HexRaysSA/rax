// Mixing functions: long multiply and xor-shift chains, and a shift register
// with a data-dependent branch in an inner loop.
//
// A bitwise CRC with a constant polynomial is deliberately absent: the
// optimizer recognizes it and substitutes a lookup in a generated table,
// which needs data segments.
#include <stdint.h>

uint64_t fmix64(uint64_t k) {
  k ^= k >> 33;
  k *= 0xff51afd7ed558ccdu;
  k ^= k >> 33;
  k *= 0xc4ceb9fe1a85ec53u;
  k ^= k >> 33;
  return k;
}

uint32_t fmix32(uint32_t h) {
  h ^= h >> 16;
  h *= 0x85ebca6bu;
  h ^= h >> 13;
  h *= 0xc2b2ae35u;
  h ^= h >> 16;
  return h;
}

uint64_t xorshift(uint64_t state, uint32_t rounds) {
  state |= 1;
  for (rounds &= 31; rounds; rounds--) {
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
  }
  return state;
}

uint32_t shift_register(uint64_t word, uint32_t taps) {
  uint32_t state = 0xffffffffu;
  taps |= 0x80000001u;
  for (int byte = 0; byte < 8; byte++) {
    state ^= (uint32_t)(word >> (8 * byte)) & 0xff;
    for (int bit = 0; bit < 8; bit++)
      state = state & 1 ? state >> 1 ^ taps : state >> 1;
  }
  return ~state;
}

uint32_t fnv1a_of_word(uint64_t word) {
  uint32_t hash = 2166136261u;
  for (int byte = 0; byte < 8; byte++) {
    hash ^= (uint32_t)(word >> (8 * byte)) & 0xff;
    hash *= 16777619u;
  }
  return hash;
}

uint64_t splitmix(uint64_t seed, uint32_t count) {
  uint64_t result = 0;
  for (count &= 15; count; count--) {
    seed += 0x9e3779b97f4a7c15u;
    uint64_t z = seed;
    z = (z ^ z >> 30) * 0xbf58476d1ce4e5b9u;
    z = (z ^ z >> 27) * 0x94d049bb133111ebu;
    result ^= z ^ z >> 31;
  }
  return result;
}
