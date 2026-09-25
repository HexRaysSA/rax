// SPDX-License-Identifier: MIT
/*
 * mem_alias_lifetime_graph.c
 *
 * Byte-backed graph records with legal aliasing and lifetime-like churn.
 * Stresses memcpy type movement, same-type pointer aliases, nested
 * structs/unions, unaligned-looking byte storage, branches, loops, and calls.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define NODE_COUNT 48u
#define WALK_COUNT 24u /* rax: was 192u */
#define SLOT_PAD 7u

typedef struct {
    uint32_t lo;
    uint32_t hi;
    uint16_t weight;
    uint8_t flags;
    uint8_t salt;
} EdgePayload;

typedef struct {
    uint8_t bytes[19];
    uint32_t stamp;
} BlobPayload;

typedef struct {
    uint64_t a;
    uint64_t b;
    uint32_t fold;
} WidePayload;

typedef union {
    EdgePayload edge;
    BlobPayload blob;
    WidePayload wide;
    uint8_t raw[32];
} Payload;

typedef struct {
    uint16_t next[3];
    uint16_t prev;
    uint16_t epoch;
    uint16_t span;
} Links;

typedef struct {
    uint32_t id;
    uint32_t generation;
    uint16_t bias;
    uint8_t tag;
    uint8_t live;
    Links links;
    Payload payload;
} GraphNode;

typedef struct {
    uint8_t raw[sizeof(GraphNode) + SLOT_PAD];
} PackedSlot;

static PackedSlot arena[NODE_COUNT];
static uint32_t visit_counts[NODE_COUNT];
static uint8_t scratch[sizeof(GraphNode) * 2u + 11u];

static uint64_t rotl64(uint64_t x, unsigned n) {
    n &= 63u;
    return n == 0u ? x : ((x << n) | (x >> (64u - n)));
}

static uint32_t rotl32(uint32_t x, unsigned n) {
    n &= 31u;
    return n == 0u ? x : ((x << n) | (x >> (32u - n)));
}

static size_t slot_offset(uint32_t idx) {
    return (size_t)((idx * 5u + 3u) & SLOT_PAD);
}

static void store_node(uint32_t idx, const GraphNode *node) {
    memcpy(arena[idx].raw + slot_offset(idx), node, sizeof(*node));
}

static void load_node(uint32_t idx, GraphNode *node) {
    memcpy(node, arena[idx].raw + slot_offset(idx), sizeof(*node));
}

static uint32_t load_u32_at(const uint8_t *base, size_t offset) {
    uint32_t value;
    memcpy(&value, base + offset, sizeof(value));
    return value;
}

static void store_u32_at(uint8_t *base, size_t offset, uint32_t value) {
    memcpy(base + offset, &value, sizeof(value));
}

static uint64_t checksum_bytes(const void *ptr, size_t len, uint64_t seed) {
    const uint8_t *p = (const uint8_t *)ptr;
    uint64_t h = seed ^ 0x9e3779b97f4a7c15ull;

    for (size_t i = 0; i < len; i++) {
        h ^= (uint64_t)p[i] + ((uint64_t)i << 17);
        h = rotl64(h, 11) * 0x100000001b3ull;
        h ^= h >> 29;
    }

    return h;
}

static GraphNode make_node(uint32_t idx, uint32_t seed) {
    GraphNode node;
    memset(&node, 0, sizeof(node));

    node.id = seed ^ (idx * 0x45d9f3bu);
    node.generation = seed + idx * 17u;
    node.bias = (uint16_t)((seed >> (idx & 7u)) ^ (idx * 29u));
    node.tag = (uint8_t)((seed + idx) % 3u);
    node.live = (uint8_t)((idx % 5u) != 0u);
    node.links.prev = (uint16_t)((idx + NODE_COUNT - 1u) % NODE_COUNT);
    node.links.epoch = (uint16_t)(seed ^ (seed >> 16));
    node.links.span = (uint16_t)(1u + (idx % 11u));

    for (uint32_t j = 0; j < 3u; j++) {
        node.links.next[j] = (uint16_t)((idx * (j + 3u) + seed + j) % NODE_COUNT);
    }

    if (node.tag == 0u) {
        node.payload.edge.lo = rotl32(seed + idx, (idx % 13u) + 1u);
        node.payload.edge.hi = seed ^ 0xa5a5c3c3u ^ (idx * 97u);
        node.payload.edge.weight = (uint16_t)(seed + idx * 7u);
        node.payload.edge.flags = (uint8_t)(seed >> 5);
        node.payload.edge.salt = (uint8_t)(idx * 31u);
    } else if (node.tag == 1u) {
        for (uint32_t j = 0; j < sizeof(node.payload.blob.bytes); j++) {
            node.payload.blob.bytes[j] = (uint8_t)(seed + idx * 13u + j * 19u);
        }
        node.payload.blob.stamp = seed ^ rotl32(idx + 0x10203u, idx & 15u);
    } else {
        node.payload.wide.a = ((uint64_t)seed << 32) | (uint64_t)(idx * 0x01010101u);
        node.payload.wide.b = rotl64(node.payload.wide.a ^ 0xd6e8feb86659fd93ull, idx + 9u);
        node.payload.wide.fold = (uint32_t)(node.payload.wide.a ^ (node.payload.wide.b >> 32));
    }

    return node;
}

__attribute__((noinline))
static uint64_t alias_mutate(GraphNode *left, GraphNode *right, uint32_t step) {
    uint64_t mix = ((uint64_t)left->id << 21) ^ right->generation ^ step;
    uint16_t edge = left->links.next[step % 3u];

    left->generation += right->bias + step + (uint32_t)left->live;
    right->bias = (uint16_t)(right->bias + left->links.span + (step & 31u));
    left->links.next[(step + left->tag) % 3u] = (uint16_t)((edge + right->bias + step) % NODE_COUNT);
    right->links.prev = (uint16_t)((left->links.prev + edge + step) % NODE_COUNT);

    if (left->tag == 0u) {
        left->payload.edge.lo ^= rotl32(right->id + step, (left->bias & 15u) + 1u);
        left->payload.edge.hi += left->payload.edge.lo ^ right->generation;
        mix ^= left->payload.edge.hi;
    } else if (left->tag == 1u) {
        uint8_t carry = (uint8_t)(right->bias ^ step);
        for (size_t i = 0; i < sizeof(left->payload.blob.bytes); i++) {
            uint8_t v = left->payload.blob.bytes[i];
            left->payload.blob.bytes[i] = (uint8_t)(v ^ carry ^ (uint8_t)(i * 23u));
            carry = (uint8_t)(carry + v + (uint8_t)i);
        }
        left->payload.blob.stamp += (uint32_t)carry + right->id;
        mix ^= left->payload.blob.stamp;
    } else {
        left->payload.wide.a += rotl64(right->payload.raw[step % sizeof(right->payload.raw)], step);
        left->payload.wide.b ^= rotl64(left->payload.wide.a + right->generation, step + 17u);
        left->payload.wide.fold = (uint32_t)(left->payload.wide.a ^ (left->payload.wide.b >> 27));
        mix ^= left->payload.wide.b;
    }

    mix ^= checksum_bytes(left, sizeof(*left), 0x3141592653589793ull + step);
    mix += checksum_bytes(right, sizeof(*right), 0x2718281828459045ull ^ mix);
    return mix;
}

__attribute__((noinline))
static uint64_t copy_retype_window(uint32_t idx, uint32_t step) {
    GraphNode first;
    GraphNode second;
    uint8_t first_tag;
    uint8_t second_tag;
    uint64_t acc;

    load_node(idx, &first);
    load_node((idx + first.links.span) % NODE_COUNT, &second);
    first_tag = first.tag;
    second_tag = second.tag;

    memset(scratch, 0, sizeof(scratch));
    memcpy(scratch + 1u, &first, sizeof(first));
    memcpy(scratch + 7u + sizeof(first), &second, sizeof(second));

    for (size_t off = 1u; off + sizeof(uint32_t) <= sizeof(first); off += 5u) {
        uint32_t word = load_u32_at(scratch, off);
        word ^= rotl32((uint32_t)off + step + first.id, (unsigned)off & 15u);
        store_u32_at(scratch, off, word);
    }

    memcpy(&first, scratch + 1u, sizeof(first));
    memcpy(&second, scratch + 7u + sizeof(first), sizeof(second));

    first.tag = first_tag;
    second.tag = second_tag;
    first.live = (uint8_t)(first.live & 1u);
    second.live = (uint8_t)(second.live & 1u);

    acc = alias_mutate(&first, (step & 4u) ? &first : &second, step);
    store_node(idx, &first);
    if ((step & 4u) == 0u) {
        store_node((idx + first.links.span) % NODE_COUNT, &second);
    }

    return acc;
}

static uint64_t walk_graph(uint32_t start) {
    uint32_t idx = start % NODE_COUNT;
    uint64_t result = 0x123456789abcdef0ull ^ start;

    for (uint32_t step = 0; step < WALK_COUNT; step++) {
        GraphNode node;
        load_node(idx, &node);

        visit_counts[idx]++;
        result ^= copy_retype_window(idx, step);
        result = rotl64(result + node.id + visit_counts[idx], (step % 23u) + 3u);

        if (((node.generation ^ node.bias ^ step) & 3u) == 0u) {
            GraphNode replacement = make_node(idx, (uint32_t)result ^ step);
            replacement.generation += visit_counts[idx];
            store_node(node.links.prev % NODE_COUNT, &replacement);
            idx = replacement.links.next[1] % NODE_COUNT;
        } else {
            idx = node.links.next[(result >> (step & 15u)) % 3u] % NODE_COUNT;
        }
    }

    return result;
}

int main(void) {
    uint64_t checksum = 0xfeedfacecafebeefull;
    uint32_t live_total = 0;

    for (uint32_t i = 0; i < NODE_COUNT; i++) {
        GraphNode node = make_node(i, 0x6d2b79f5u + i * 0x9e3779b9u);
        store_node(i, &node);
    }

    for (uint32_t pass = 0; pass < 3u; pass++) { /* rax: was 19u */
        checksum ^= walk_graph(pass * 7u + (uint32_t)checksum);
        checksum = rotl64(checksum, pass + 5u) + 0x94d049bb133111ebull;
    }

    for (uint32_t i = 0; i < NODE_COUNT; i++) {
        GraphNode node;
        load_node(i, &node);
        live_total += node.live;
        checksum ^= checksum_bytes(&node, sizeof(node), (uint64_t)i * 0x100000001b3ull);
        checksum += visit_counts[i] * 0x45d9f3bu;
    }

    printf("mem_alias_lifetime_graph: %08x %016llx\n",
           (unsigned)live_total, (unsigned long long)checksum);
    return 0;
}
