/*
 * mem_unaligned_packed.c
 *
 * Packed/unaligned memory access patterns.
 * Stresses unaligned loads/stores and packed layouts.
 *
 * Features exercised:
 *   - Packed structs with misaligned fields
 *   - Unaligned 64-bit accesses via packed fields
 *   - Volatile packed loads/stores
 *   - Mixed-size field access
 */

#include <stdint.h>
#include <inttypes.h> /* rax: print the result so that runs can be compared */
#include <stdio.h>

volatile uint64_t sink;

typedef struct __attribute__((packed)) {
    uint8_t tag;
    uint16_t len;
    uint32_t id;
    uint64_t payload;
} PackedRecord;

typedef struct __attribute__((packed, aligned(1))) {
    uint8_t pad;
    PackedRecord recs[8];
    uint16_t tail;
} PackedBlock;

typedef struct __attribute__((packed)) {
    uint8_t head;
    uint8_t bytes[7];
    uint64_t tail;
} PackedTail;

__attribute__((noinline))
void init_block(volatile PackedBlock *block, uint32_t seed) {
    block->pad = (uint8_t)seed;
    block->tail = (uint16_t)(seed ^ 0x5a5au);

    for (int i = 0; i < 8; i++) {
        block->recs[i].tag = (uint8_t)(seed + i);
        block->recs[i].len = (uint16_t)((seed >> 1) + i * 3);
        block->recs[i].id = seed ^ (uint32_t)(i * 0x9e37u);
        block->recs[i].payload = ((uint64_t)block->recs[i].id << 32) |
                                 (uint64_t)(block->recs[i].len | (block->recs[i].tag << 16));
    }
}

__attribute__((noinline))
uint64_t sum_packed(const volatile PackedBlock *block) {
    uint64_t sum = 0;

    sum += block->pad;
    sum += block->tail;

    for (int i = 0; i < 8; i++) {
        sum += block->recs[i].tag;
        sum += block->recs[i].len;
        sum += block->recs[i].id;
        sum ^= block->recs[i].payload;
        sum += block->recs[i].payload >> 32;
    }

    return sum;
}

__attribute__((noinline))
uint64_t mix_tail(volatile PackedTail *tail, uint32_t seed) {
    tail->head = (uint8_t)(seed ^ 0xa5u);
    for (int i = 0; i < 7; i++) {
        tail->bytes[i] = (uint8_t)(seed + i * 11);
    }
    tail->tail = ((uint64_t)seed << 48) | ((uint64_t)seed << 16) | (uint64_t)seed;

    uint64_t sum = tail->head;
    for (int i = 0; i < 7; i++) {
        sum += tail->bytes[i];
    }
    sum ^= tail->tail;
    sum += tail->tail >> 17;
    return sum;
}

int main(void) {
    uint64_t result = 0;
    volatile PackedBlock block;
    volatile PackedTail tail;

    for (uint32_t i = 0; i < 200; i++) { /* rax: was 1000 */
        init_block(&block, i * 3u + 1u);
        result += sum_packed(&block);
        result += mix_tail(&tail, i ^ 0x1234u);
    }

    sink = result;
    printf("sink=%016" PRIx64 "\n", (uint64_t)sink); /* rax: print the result so that runs can be compared */
    return 0;
}
