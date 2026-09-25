// SPDX-License-Identifier: MIT
/*
 * mem_flexible_arena_rewriter.c
 *
 * Flexible-array variable records in a malloc-backed arena. The workload
 * rewrites payloads, preserves links through compaction, and moves typed data
 * with memcpy/memmove rather than aliasing through incompatible types.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RECORD_COUNT 32u /* rax: was 56u */
#define PASS_COUNT 5u /* rax: was 31u */
#define ARENA_CAPACITY 8192u
#define NO_OFFSET UINT32_MAX

typedef struct {
    uint32_t id;
    uint32_t next_off;
    uint32_t aux;
    uint16_t len;
    uint8_t kind;
    uint8_t live;
    uint64_t stamp;
    uint8_t payload[];
} ArenaRecord;

typedef struct {
    uint8_t *bytes;
    size_t used;
    size_t capacity;
} Arena;

typedef struct {
    uint32_t old_off[RECORD_COUNT];
    uint32_t new_off[RECORD_COUNT];
    uint32_t count;
} RewriteMap;

static uint32_t rotl32(uint32_t x, unsigned n) {
    n &= 31u;
    return n == 0u ? x : ((x << n) | (x >> (32u - n)));
}

static uint64_t rotl64(uint64_t x, unsigned n) {
    n &= 63u;
    return n == 0u ? x : ((x << n) | (x >> (64u - n)));
}

static uint32_t mix32(uint32_t x) {
    x += 0x9e3779b9u;
    x = (x ^ (x >> 16)) * 0x85ebca6bu;
    x = (x ^ (x >> 13)) * 0xc2b2ae35u;
    return x ^ (x >> 16);
}

static uint32_t load32_bytes(const uint8_t *p) {
    uint32_t v;
    memcpy(&v, p, sizeof(v));
    return v;
}

static void store32_bytes(uint8_t *p, uint32_t v) {
    memcpy(p, &v, sizeof(v));
}

static size_t align_up_size(size_t value, size_t align) {
    return (value + align - 1u) & ~(align - 1u);
}

static size_t record_span_len(uint16_t len) {
    return align_up_size(sizeof(ArenaRecord) + (size_t)len, _Alignof(ArenaRecord));
}

static size_t record_span(const ArenaRecord *record) {
    return record_span_len(record->len);
}

static ArenaRecord *record_at(Arena *arena, uint32_t off) {
    return (ArenaRecord *)(void *)(arena->bytes + off);
}

static const ArenaRecord *record_at_const(const Arena *arena, uint32_t off) {
    return (const ArenaRecord *)(const void *)(arena->bytes + off);
}

static uint64_t checksum_bytes(const void *data, size_t len, uint64_t seed) {
    const uint8_t *p = (const uint8_t *)data;
    uint64_t h = seed ^ 0xcbf29ce484222325ull;

    for (size_t i = 0; i < len; i++) {
        h ^= (uint64_t)p[i] + ((uint64_t)i << 13);
        h *= 0x100000001b3ull;
        h = rotl64(h, 7) ^ (h >> 25);
    }

    return h;
}

static int arena_init(Arena *arena, size_t capacity) {
    arena->bytes = (uint8_t *)malloc(capacity);
    arena->used = 0u;
    arena->capacity = capacity;
    if (arena->bytes == NULL) {
        return 0;
    }
    memset(arena->bytes, 0, capacity);
    return 1;
}

static void arena_destroy(Arena *arena) {
    free(arena->bytes);
    arena->bytes = NULL;
    arena->used = 0u;
    arena->capacity = 0u;
}

static uint32_t arena_append(Arena *arena, uint32_t id, uint16_t len, uint8_t kind, uint32_t seed) {
    size_t aligned = align_up_size(arena->used, _Alignof(ArenaRecord));
    size_t span = record_span_len(len);
    ArenaRecord header;
    ArenaRecord *record;

    if (aligned + span > arena->capacity || aligned > UINT32_MAX) {
        return NO_OFFSET;
    }

    memset(arena->bytes + arena->used, 0, aligned - arena->used);
    memset(&header, 0, sizeof(header));
    header.id = id;
    header.next_off = NO_OFFSET;
    header.aux = mix32(seed + id);
    header.len = len;
    header.kind = kind;
    header.live = 1u;
    header.stamp = ((uint64_t)mix32(id ^ seed) << 32) | mix32(seed + len + kind);

    memcpy(arena->bytes + aligned, &header, sizeof(header));
    record = record_at(arena, (uint32_t)aligned);

    for (uint32_t i = 0; i < len; i++) {
        uint32_t v = mix32(seed + id * 17u + i * 29u + kind);
        record->payload[i] = (uint8_t)(v ^ (v >> 9) ^ (i * 7u));
    }

    memset(arena->bytes + aligned + sizeof(ArenaRecord) + len, 0, span - sizeof(ArenaRecord) - len);
    arena->used = aligned + span;
    return (uint32_t)aligned;
}

static uint32_t map_lookup(const RewriteMap *map, uint32_t old_off) {
    for (uint32_t i = 0; i < map->count; i++) {
        if (map->old_off[i] == old_off) {
            return map->new_off[i];
        }
    }
    return NO_OFFSET;
}

__attribute__((noinline))
static uint64_t rewrite_record(ArenaRecord *record, uint32_t pass, uintptr_t token) {
    uint64_t acc = record->stamp ^ ((uint64_t)record->id << 17) ^ token;
    uint32_t stride = 3u + (record->kind % 5u);

    for (uint32_t i = 0; i + sizeof(uint32_t) <= record->len; i += stride) {
        uint32_t v = load32_bytes(record->payload + i);
        if (((v ^ record->aux ^ pass ^ (uint32_t)token) & 1u) != 0u) {
            v = rotl32(v + record->id + pass, (record->kind + i) & 31u);
        } else {
            v ^= mix32(record->aux + i + pass);
        }
        store32_bytes(record->payload + i, v);
        acc ^= v;
        acc = rotl64(acc + i + record->kind, 11);
    }

    for (uint32_t i = 0; i < record->len; i++) {
        uint8_t old = record->payload[i];
        record->payload[i] = (uint8_t)(old ^ (uint8_t)(record->aux >> ((i & 3u) * 8u)) ^ (uint8_t)pass);
        acc += record->payload[i] + (uint64_t)i;
    }

    record->aux = mix32(record->aux + (uint32_t)acc + pass);
    record->stamp = rotl64(record->stamp ^ acc ^ token, (pass % 37u) + 1u);
    if (((record->aux + pass + record->kind) % 19u) == 0u) {
        record->live = 0u;
    }
    return acc;
}

__attribute__((noinline))
static uint64_t compact_arena(Arena *arena, uint32_t pass) {
    Arena next;
    RewriteMap map;
    uint32_t scan = 0u;
    uint64_t acc = 0x510e527fade682d1ull ^ pass;

    map.count = 0u;
    if (!arena_init(&next, arena->capacity)) {
        return 0u;
    }

    while ((size_t)scan < arena->used) {
        const ArenaRecord *src = record_at_const(arena, scan);
        size_t span = record_span(src);
        size_t aligned = align_up_size(next.used, _Alignof(ArenaRecord));

        if (src->live != 0u) {
            if (aligned + span <= next.capacity && map.count < RECORD_COUNT) {
                memset(next.bytes + next.used, 0, aligned - next.used);
                memmove(next.bytes + aligned, src, span);
                map.old_off[map.count] = scan;
                map.new_off[map.count] = (uint32_t)aligned;
                map.count++;
                next.used = aligned + span;
            }
        } else {
            acc ^= checksum_bytes(src, span, src->stamp + pass);
        }

        scan = (uint32_t)((size_t)scan + span);
    }

    for (uint32_t i = 0; i < map.count; i++) {
        ArenaRecord *record = record_at(&next, map.new_off[i]);
        uint32_t old_next = record->next_off;

        record->next_off = map_lookup(&map, old_next);
        if (record->next_off == NO_OFFSET && map.count != 0u) {
            record->next_off = map.new_off[(i + pass + record->kind) % map.count];
        }
        record->stamp ^= ((uint64_t)map.old_off[i] << 32) | map.new_off[i];
        acc ^= rewrite_record(record, pass + i, (uintptr_t)(size_t)i);
    }

    free(arena->bytes);
    *arena = next;
    return acc ^ ((uint64_t)map.count << 48);
}

static uint64_t run_pass(Arena *arena, uint32_t pass) {
    uint32_t offsets[RECORD_COUNT];
    uint32_t count = 0u;
    uint32_t scan = 0u;
    uint64_t acc = 0x1f83d9abfb41bd6bull ^ pass;

    while ((size_t)scan < arena->used && count < RECORD_COUNT) {
        ArenaRecord *record = record_at(arena, scan);
        offsets[count++] = scan;
        acc ^= rewrite_record(record, pass, (uintptr_t)(size_t)count);
        scan = (uint32_t)((size_t)scan + record_span(record));
    }

    for (uint32_t i = 0; i < count; i++) {
        ArenaRecord *record = record_at(arena, offsets[i]);
        if (record->next_off != NO_OFFSET) {
            ArenaRecord *next = record_at(arena, record->next_off);
            uint32_t sample = next->len >= sizeof(uint32_t) ? load32_bytes(next->payload) : next->aux;
            record->aux ^= rotl32(sample + pass + i, record->kind + 1u);
            record->stamp += ((uint64_t)next->id << (i & 7u)) ^ record->aux;
        }
        if (((record->id ^ record->aux ^ pass) & 7u) == 3u && count != 0u) {
            record->next_off = offsets[(i * 7u + pass + record->kind) % count];
        }
        acc += checksum_bytes(record, record_span(record), record->stamp ^ i);
    }

    if ((pass % 5u) == 4u) {
        acc ^= compact_arena(arena, pass);
    }

    return acc;
}

int main(void) {
    Arena arena;
    uint32_t offsets[RECORD_COUNT];
    uint32_t count = 0u;
    uint64_t checksum = 0x6a09e667f3bcc908ull;
    uint32_t live_total = 0u;
    uint32_t scan;

    if (!arena_init(&arena, ARENA_CAPACITY)) {
        printf("mem_flexible_arena_rewriter: alloc-failed\n");
        return 1;
    }

    for (uint32_t i = 0; i < RECORD_COUNT; i++) {
        uint16_t len = (uint16_t)(9u + ((i * 17u + 5u) % 43u));
        uint32_t off = arena_append(&arena, 0x1000u + i * 37u, len, (uint8_t)(i % 6u),
                                    0x243f6a88u + i * 0x9e37u);
        if (off == NO_OFFSET) {
            arena_destroy(&arena);
            printf("mem_flexible_arena_rewriter: append-failed\n");
            return 1;
        }
        offsets[count++] = off;
    }

    for (uint32_t i = 0; i < count; i++) {
        ArenaRecord *record = record_at(&arena, offsets[i]);
        record->next_off = offsets[(i * 11u + record->kind + 3u) % count];
    }

    for (uint32_t pass = 0; pass < PASS_COUNT; pass++) {
        checksum ^= run_pass(&arena, pass);
        checksum = rotl64(checksum + pass * 0x94d049bb133111ebull, (pass % 29u) + 3u);
    }

    scan = 0u;
    while ((size_t)scan < arena.used) {
        ArenaRecord *record = record_at(&arena, scan);
        live_total += record->live;
        checksum ^= checksum_bytes(record, record_span(record), record->stamp + scan);
        scan = (uint32_t)((size_t)scan + record_span(record));
    }

    printf("mem_flexible_arena_rewriter: %08x %08x %016llx\n",
           (unsigned)live_total, (unsigned)arena.used, (unsigned long long)checksum);

    arena_destroy(&arena);
    return 0;
}
