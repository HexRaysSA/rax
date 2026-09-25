/*
 * cf_irreducible_state_maze.c
 *
 * Goto-heavy state maze with multi-entry loops and opaque-ish predicates.
 * Stresses PHIs, switches, pointer aliasing, and hard-to-structure control flow.
 */

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>

volatile uint32_t cf_irreducible_fence;
volatile uint64_t cf_irreducible_sink;

typedef struct {
    uint32_t pc;
    uint32_t a;
    uint32_t b;
    uint32_t c;
    uint32_t d;
    uint16_t stack[8];
    uint8_t tape[64];
} Maze;

static uint32_t rotl32(uint32_t value, unsigned amount) {
    amount &= 31u;
    return amount == 0u ? value : (value << amount) | (value >> (32u - amount));
}

static uint32_t mix32(uint32_t value) {
    value ^= value >> 16u;
    value *= UINT32_C(0x7feb352d);
    value ^= value >> 15u;
    value *= UINT32_C(0x846ca68b);
    value ^= value >> 16u;
    return value;
}

__attribute__((noinline))
static uint32_t scramble_slot(Maze *maze, uint32_t index, uint32_t salt) {
    uint8_t *bytes = maze->tape;
    uint16_t *slot = &maze->stack[index & 7u];
    uint8_t *nearby = &bytes[(index * 9u + salt) & 63u];

    uint32_t before = (uint32_t)*slot;
    uint32_t folded = mix32(before ^ salt ^ bytes[(index + 17u) & 63u]);
    *slot = (uint16_t)(before + (folded & UINT32_C(0xffff)));
    *nearby = (uint8_t)((uint32_t)*nearby ^ (folded >> ((index & 3u) * 8u)));

    return folded ^ (uint32_t)*slot ^ (uint32_t)*nearby;
}

__attribute__((noinline))
static uint32_t run_maze(Maze *maze, uint32_t seed) {
    uint32_t acc = seed ^ UINT32_C(0x9e3779b9);
    uint32_t tag = (seed >> 3u) & 15u;
    uint32_t latch = mix32(seed + UINT32_C(0x632be59b));
    uint32_t steps = 0;
    const uint32_t max_steps = 96u + (seed & 31u);

#define MAZE_FUEL() do {                 \
        if (++steps >= max_steps) {      \
            goto Exit;                   \
        }                                \
    } while (0)

    if (((mix32(seed) ^ seed ^ cf_irreducible_fence) & 3u) == 0u) {
        goto Cross;
    }
    goto North;

Hub:
    MAZE_FUEL();
    maze->pc = (maze->pc + tag + (acc & 7u)) & 31u;
    acc ^= scramble_slot(maze, maze->pc + steps, latch);
    cf_irreducible_fence = acc ^ maze->pc;

    switch ((acc ^ latch ^ maze->pc) & 7u) {
        case 0u: goto North;
        case 1u: goto East;
        case 2u: goto South;
        case 3u: goto West;
        case 4u: goto Cross;
        case 5u: goto Fold;
        case 6u: goto Spill;
        default: goto Trap;
    }

North:
    MAZE_FUEL();
    maze->a += rotl32(acc + maze->pc, (tag & 7u) + 1u);
    latch ^= maze->a + UINT32_C(0x45d9f3b);
    tag = (tag + ((maze->a >> 27u) | 1u)) & 15u;
    if (((maze->a ^ maze->c ^ cf_irreducible_fence) & 5u) == 0u) {
        goto Cross;
    }
    if ((tag & 1u) != 0u) {
        goto East;
    }
    goto Hub;

East:
    MAZE_FUEL();
    maze->b ^= rotl32(latch + maze->stack[tag & 7u], (maze->a >> 29u) + 3u);
    acc += maze->b ^ maze->tape[(maze->b + tag) & 63u];
    if (((acc + maze->d) & 7u) == 2u) {
        goto South;
    }
    if ((maze->b & UINT32_C(0x1040)) == UINT32_C(0x1000)) {
        goto Fold;
    }
    goto Cross;

South:
    MAZE_FUEL();
    maze->c += mix32(acc ^ maze->b ^ steps);
    maze->tape[(maze->c >> 3u) & 63u] =
        (uint8_t)(maze->tape[(maze->c >> 11u) & 63u] + tag + steps);
    latch += maze->c | UINT32_C(1);
    if (((maze->c ^ latch) & 3u) == 1u) {
        goto West;
    }
    if ((steps & 5u) == 5u) {
        goto Cross;
    }
    goto Hub;

West:
    MAZE_FUEL();
    maze->d = rotl32(maze->d ^ acc ^ maze->a, (steps & 15u) + 1u);
    acc ^= maze->d + maze->stack[(steps + tag) & 7u];
    if (((maze->d + cf_irreducible_fence) & 11u) == 8u) {
        goto North;
    }
    if ((acc & 9u) == 9u) {
        goto Spill;
    }
    goto Hub;

Cross:
    MAZE_FUEL();
    acc = mix32(acc + maze->a + (maze->b ^ maze->c));
    maze->stack[(acc >> 5u) & 7u] ^=
        (uint16_t)(acc + maze->d + (uint32_t)maze->tape[acc & 63u]);
    if (((acc ^ tag) & 13u) == 4u) {
        goto South;
    }
    if (((acc >> 8u) & 3u) == 0u) {
        goto Fold;
    }
    goto West;

Fold:
    MAZE_FUEL();
    {
        uint32_t left = maze->stack[(tag + 1u) & 7u];
        uint32_t right = maze->tape[(acc + steps) & 63u];
        acc += mix32((left << 16u) | right);
        maze->a ^= acc + left;
        maze->c ^= rotl32(right + latch, (tag & 7u) + 1u);
    }
    if ((maze->a & maze->c & 1u) != 0u) {
        goto East;
    }
    goto Hub;

Spill:
    MAZE_FUEL();
    {
        uint32_t first = (steps + maze->pc) & 63u;
        uint32_t second = (first + 23u + tag) & 63u;
        uint8_t tmp = maze->tape[first];
        maze->tape[first] = (uint8_t)(maze->tape[second] + acc);
        maze->tape[second] = (uint8_t)(tmp ^ (latch >> 24u));
        acc ^= ((uint32_t)maze->tape[first] << 8u) | maze->tape[second];
    }
    if (((acc ^ steps) & 6u) == 6u) {
        goto Trap;
    }
    goto Cross;

Trap:
    MAZE_FUEL();
    latch = mix32(latch ^ acc ^ UINT32_C(0xa5a5a5a5));
    maze->b += latch | 1u;
    tag = (tag + 7u + (latch & 3u)) & 15u;
    if ((latch & 0x80u) != 0u) {
        goto North;
    }
    goto Hub;

Exit:
#undef MAZE_FUEL
    return mix32(acc ^ latch ^ maze->a ^ rotl32(maze->b, 7u) ^
                 rotl32(maze->c, 13u) ^ rotl32(maze->d, 19u) ^ steps);
}

int main(void) {
    Maze maze;
    uint64_t checksum = UINT64_C(0x6a09e667f3bcc909);

    maze.pc = 0;
    maze.a = UINT32_C(0x243f6a88);
    maze.b = UINT32_C(0x85a308d3);
    maze.c = UINT32_C(0x13198a2e);
    maze.d = UINT32_C(0x03707344);

    for (uint32_t i = 0; i < 8u; ++i) {
        maze.stack[i] = (uint16_t)(UINT32_C(0x1357) + i * UINT32_C(0x2221));
    }
    for (uint32_t i = 0; i < 64u; ++i) {
        maze.tape[i] = (uint8_t)(mix32(i * UINT32_C(37) + UINT32_C(11)) >> 24u);
    }

    for (uint32_t round = 0; round < 64u; ++round) { /* rax: was 4096u */
        uint32_t seed = mix32(round ^ (uint32_t)checksum ^ (uint32_t)(checksum >> 32u));
        uint32_t out = run_maze(&maze, seed);
        checksum ^= (uint64_t)out + UINT64_C(0x9e3779b97f4a7c15) +
                    (checksum << 6u) + (checksum >> 2u);
        checksum = (checksum << 17u) | (checksum >> 47u);
    }

    cf_irreducible_sink = checksum ^ maze.a ^ ((uint64_t)maze.d << 32u);
    printf("cf_irreducible_state_maze %016" PRIx64 "\n", cf_irreducible_sink);
    return 0;
}
