// Stack memory: arrays, structures, pointers to both, pointers stored in
// memory, byte views of wider objects and pointer arithmetic.
//
// Aggregates are filled and copied element by element. Whole-aggregate
// initializers and assignments compile to bulk memory operations, which are
// tested separately.
#include <stdint.h>

static uint32_t next_random(uint32_t *state) {
  *state = *state * 1664525u + 1013904223u;
  return *state >> 8;
}

uint32_t sort_checksum(uint32_t seed) {
  uint32_t values[12];
  for (int i = 0; i < 12; i++)
    values[i] = next_random(&seed) & 0xfff;
  for (int i = 1; i < 12; i++) {
    uint32_t key = values[i];
    int j = i - 1;
    while (j >= 0 && values[j] > key) {
      values[j + 1] = values[j];
      j--;
    }
    values[j + 1] = key;
  }
  uint32_t checksum = 0;
  for (int i = 0; i < 12; i++)
    checksum = checksum * 31 + values[i] + (i > 0 && values[i - 1] > values[i]);
  return checksum;
}

int32_t binary_search(uint32_t needle) {
  uint32_t table[16];
  for (uint32_t i = 0; i < 16; i++)
    table[i] = i * i + 3 * i;
  needle &= 0x1ff;
  int32_t low = 0, high = 15;
  while (low <= high) {
    int32_t middle = low + (high - low) / 2;
    if (table[middle] == needle)
      return middle;
    if (table[middle] < needle)
      low = middle + 1;
    else
      high = middle - 1;
  }
  return -1 - low;
}

struct point {
  int32_t x, y;
};

struct shape {
  uint8_t kind;
  struct point origin;
  uint16_t flags;
  uint64_t area;
};

static void set_point(struct point *p, int32_t x, int32_t y) {
  p->x = x;
  p->y = y;
}

static void describe(struct shape *shape, uint32_t a, uint32_t b) {
  shape->kind = (uint8_t)(a & 3);
  set_point(&shape->origin, (int32_t)(a >> 4), (int32_t)(b >> 4));
  shape->flags = (uint16_t)(a ^ b);
  shape->area = (uint64_t)a * b;
}

uint64_t structure_fields(uint32_t a, uint32_t b) {
  struct shape shape;
  describe(&shape, a, b);
  return shape.kind + (uint64_t)(uint32_t)shape.origin.x * 3 + (uint64_t)(uint32_t)shape.origin.y * 5 +
         shape.flags * 7 + shape.area;
}

static void minimum_maximum(const uint32_t *values, uint32_t count, uint32_t *minimum, uint32_t *maximum) {
  *minimum = *maximum = values[0];
  for (uint32_t i = 1; i < count; i++) {
    if (values[i] < *minimum)
      *minimum = values[i];
    if (values[i] > *maximum)
      *maximum = values[i];
  }
}

uint64_t out_parameters(uint32_t seed) {
  uint32_t values[9], minimum, maximum;
  for (int i = 0; i < 9; i++)
    values[i] = next_random(&seed);
  minimum_maximum(values, 9, &minimum, &maximum);
  return (uint64_t)maximum << 32 | minimum;
}

uint32_t matrix_trace(uint32_t seed) {
  uint32_t a[3][3], b[3][3], product[3][3];
  for (int i = 0; i < 3; i++)
    for (int j = 0; j < 3; j++) {
      a[i][j] = next_random(&seed) & 0xff;
      b[i][j] = next_random(&seed) & 0xff;
    }
  for (int i = 0; i < 3; i++)
    for (int j = 0; j < 3; j++) {
      product[i][j] = 0;
      for (int k = 0; k < 3; k++)
        product[i][j] += a[i][k] * b[k][j];
    }
  return product[0][0] + product[1][1] + product[2][2] + product[0][2] * 3;
}

struct node {
  uint32_t value;
  struct node *next;
};

uint32_t linked_list(uint32_t seed) {
  struct node nodes[8];
  struct node *head = 0;
  // Push each node at the front, so the list ends up in reverse order.
  for (int i = 0; i < 8; i++) {
    nodes[i].value = next_random(&seed) & 0xffff;
    nodes[i].next = head;
    head = &nodes[i];
  }
  uint32_t sum = 0, position = 0;
  for (struct node *cursor = head; cursor; cursor = cursor->next)
    sum += cursor->value * ++position;
  return sum;
}

uint32_t pointer_walk(uint32_t seed) {
  uint16_t buffer[10];
  uint16_t *end = buffer + 10;
  for (uint16_t *cursor = buffer; cursor != end; cursor++)
    *cursor = (uint16_t)next_random(&seed);
  uint32_t total = 0;
  for (uint16_t *cursor = end; cursor > buffer;)
    total = total * 3 + *--cursor;
  return total + (uint32_t)(end - buffer);
}

uint32_t pointer_order(uint32_t i, uint32_t j) {
  uint32_t slots[8];
  uint32_t *p = &slots[i & 7], *q = &slots[j & 7];
  return (p < q) + 2 * (p == q) + 4 * (p >= q) + 8 * (uint32_t)(q - p);
}

uint32_t byte_view(uint64_t word) {
  // Reading an object through unsigned char is always defined.
  const unsigned char *bytes = (const unsigned char *)&word;
  uint32_t sum = 0;
  for (int i = 0; i < 8; i++)
    sum = sum * 257 + bytes[i];
  return sum;
}

uint64_t byte_patch(uint64_t word, uint32_t position) {
  unsigned char *bytes = (unsigned char *)&word;
  bytes[position & 7] ^= 0x5a;
  bytes[(position + 3) & 7] = (unsigned char)position;
  return word;
}

uint32_t pointer_table(uint32_t selector) {
  uint32_t a = 11, b = 22, c = 33, d = 44;
  uint32_t *table[4];
  table[0] = &a;
  table[1] = &b;
  table[2] = &c;
  table[3] = &d;
  *table[selector & 3] += selector;
  uint32_t **cursor = &table[(selector >> 2) & 3];
  **cursor *= 2;
  return a + b * 3 + c * 5 + d * 7;
}

uint32_t copy_reverse(uint32_t seed) {
  uint8_t source[13], target[13];
  for (int i = 0; i < 13; i++)
    source[i] = (uint8_t)next_random(&seed);
  for (int i = 0; i < 13; i++)
    target[12 - i] = source[i];
  uint32_t hash = 0;
  for (int i = 0; i < 13; i++)
    hash = hash * 131 + target[i] + (target[i] == source[12 - i]);
  return hash;
}

// Stack objects whose size is known only when they are made.
uint32_t variable_length(uint32_t seed, uint32_t count) {
  uint32_t length = count % 40 + 1;
  uint32_t values[length];
  for (uint32_t i = 0; i < length; i++)
    values[i] = seed = seed * 1664525u + 1013904223u;
  uint64_t wide[length / 2 + 1];
  for (uint32_t i = 0; i <= length / 2; i++)
    wide[i] = (uint64_t)values[i] << 13 ^ values[length - 1 - i];
  uint32_t hash = length + (uint32_t)(sizeof values + sizeof wide);
  for (uint32_t i = 0; i <= length / 2; i++)
    hash = hash * 31 + (uint32_t)(wide[i] ^ wide[i] >> 29);
  return hash;
}

uint32_t allocated_in_a_loop(uint32_t seed, uint32_t rounds) {
  uint32_t hash = 0;
  for (uint32_t round = 0; round < rounds % 12; round++) {
    // A new object each time around; the earlier ones are still there.
    uint8_t *bytes = __builtin_alloca(round + 5);
    uint16_t scratch[round % 3 + 2];
    for (uint32_t i = 0; i < round + 5; i++)
      bytes[i] = (uint8_t)(seed >> (i & 7)) + (uint8_t)round;
    scratch[0] = bytes[round + 4];
    scratch[round % 3 + 1] = bytes[0];
    hash = hash * 131 + scratch[0] + scratch[round % 3 + 1] * 3u + bytes[round / 2];
  }
  return hash;
}
