// SPDX-License-Identifier: MIT
/*
 * Duff's-device parser/state machine.
 *
 * The parser consumes deterministic in-memory command streams through an
 * unrolled Duff loop. Each byte also drives nested switches, parser state,
 * indirect parser actions, pointer movement, and rolling integer state.
 */

#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

typedef enum {
    ST_SEEK = 0,
    ST_KEY,
    ST_VALUE,
    ST_ARRAY,
    ST_QUOTE,
    ST_SKIP
} ParseState;

typedef enum {
    CC_ALPHA = 0,
    CC_DIGIT,
    CC_SIGN,
    CC_EQ,
    CC_SEMI,
    CC_COMMA,
    CC_OPEN,
    CC_CLOSE,
    CC_QUOTE,
    CC_OTHER
} CharClass;

typedef struct Parser Parser;
typedef uint32_t (*ParserAction)(Parser *, uint32_t, uint32_t);

struct Parser {
    const unsigned char *base;
    const unsigned char *cursor;
    const unsigned char *end;
    uint32_t hash;
    uint32_t key;
    uint32_t value;
    uint32_t items;
    uint32_t depth;
    uint32_t state;
    uint32_t sign;
    uint32_t lanes[8];
    uint8_t window[64];
};

volatile uint32_t cf_duff_device_parser_fence;
volatile uint64_t cf_duff_device_parser_sink;

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

static uint32_t lower_alpha(uint32_t ch) {
    if (ch >= 'A' && ch <= 'Z') {
        return ch + ('a' - 'A');
    }
    return ch;
}

__attribute__((noinline))
static uint32_t classify(uint32_t ch) {
    if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch == '_') {
        return CC_ALPHA;
    }
    if (ch >= '0' && ch <= '9') {
        return CC_DIGIT;
    }
    switch (ch) {
        case '+':
        case '-':
            return CC_SIGN;
        case '=':
        case ':':
            return CC_EQ;
        case ';':
        case '\n':
            return CC_SEMI;
        case ',':
            return CC_COMMA;
        case '[':
        case '{':
        case '(':
            return CC_OPEN;
        case ']':
        case '}':
        case ')':
            return CC_CLOSE;
        case '"':
        case '\'':
            return CC_QUOTE;
        default:
            return CC_OTHER;
    }
}

__attribute__((noinline))
static uint32_t action_lace(Parser *parser, uint32_t ch, uint32_t cls) {
    uint32_t lane = (parser->items + cls + parser->state) & 7u;
    parser->lanes[lane] ^= mix32(ch + parser->hash + parser->key);
    return rotl32(parser->lanes[lane], lane + 1u);
}

__attribute__((noinline))
static uint32_t action_stride(Parser *parser, uint32_t ch, uint32_t cls) {
    uint32_t pos = (uint32_t)(parser->cursor - parser->base);
    uint32_t slot = (pos * 5u + cls + parser->depth) & 63u;
    parser->window[slot] = (uint8_t)(parser->window[(slot + 17u) & 63u] ^ ch ^ parser->state);
    return mix32((uint32_t)parser->window[slot] + pos + (parser->depth << 8u));
}

__attribute__((noinline))
static uint32_t action_gate(Parser *parser, uint32_t ch, uint32_t cls) {
    uint32_t lane = (ch + parser->state + parser->depth) & 7u;
    uint32_t mask = 0u - ((cls ^ parser->items) & 1u);
    parser->lanes[lane] = (parser->lanes[lane] & mask) |
                          (rotl32(parser->hash, lane + 9u) & ~mask);
    return parser->lanes[lane] ^ mask;
}

__attribute__((noinline))
static uint32_t action_echo(Parser *parser, uint32_t ch, uint32_t cls) {
    uint32_t lane = (parser->key + parser->value + cls) & 7u;
    parser->lanes[lane] += mix32((ch << 16u) ^ parser->hash ^ parser->items);
    return parser->lanes[lane] + rotl32(ch + cls, (lane & 7u) + 1u);
}

static ParserAction action_table[4] = {
    action_lace,
    action_stride,
    action_gate,
    action_echo
};

static void emit_value(Parser *parser, uint32_t tag) {
    uint32_t encoded = parser->sign != 0u ? (~parser->value + 1u) : parser->value;
    uint32_t lane = (parser->items + parser->depth + tag) & 7u;

    parser->lanes[lane] ^= mix32(parser->key + rotl32(encoded, lane + 3u) + tag);
    parser->hash += mix32(parser->lanes[lane] ^ parser->items ^ parser->state);
    parser->items++;
    parser->value = 0u;
    parser->key = mix32(parser->key ^ tag) & UINT32_C(0x00ffffff);
    parser->sign = 0u;
}

__attribute__((noinline))
static void parse_one(Parser *parser) {
    uint32_t pos = (uint32_t)(parser->cursor - parser->base);
    uint32_t ch = *parser->cursor++;
    uint32_t cls = classify(ch);
    uint32_t old_state = parser->state;
    ParserAction action = action_table[(cls ^ old_state ^ (ch >> 4u)) & 3u];

    parser->window[(pos + old_state * 11u) & 63u] =
        (uint8_t)(ch ^ parser->depth ^ parser->items);
    parser->hash ^= action(parser, ch, cls);
    cf_duff_device_parser_fence = parser->hash ^ pos;

    switch (parser->state) {
        case ST_SEEK:
            switch (cls) {
                case CC_ALPHA:
                    parser->key = lower_alpha(ch) ^ UINT32_C(0x9e37);
                    parser->state = ST_KEY;
                    break;
                case CC_OPEN:
                    parser->depth++;
                    parser->hash += mix32(ch + parser->depth);
                    break;
                case CC_CLOSE:
                    if (parser->depth != 0u) {
                        parser->depth--;
                    }
                    parser->hash ^= mix32(ch + parser->depth);
                    break;
                default:
                    parser->hash += cls + ch;
                    break;
            }
            break;

        case ST_KEY:
            switch (cls) {
                case CC_ALPHA:
                case CC_DIGIT:
                    parser->key = parser->key * 33u + lower_alpha(ch) + (parser->depth << 3u);
                    break;
                case CC_EQ:
                    parser->state = ST_VALUE;
                    parser->value = 0u;
                    parser->sign = 0u;
                    break;
                case CC_OPEN:
                    parser->depth++;
                    parser->state = ST_ARRAY;
                    break;
                case CC_SEMI:
                case CC_COMMA:
                    emit_value(parser, cls);
                    parser->state = ST_SEEK;
                    break;
                default:
                    parser->state = ST_SKIP;
                    parser->hash ^= mix32(parser->key + ch);
                    break;
            }
            break;

        case ST_VALUE:
            switch (cls) {
                case CC_DIGIT:
                    parser->value = parser->value * 10u + (ch - '0');
                    break;
                case CC_SIGN:
                    parser->sign ^= (ch == '-') ? 1u : 0u;
                    parser->hash += ch;
                    break;
                case CC_ALPHA:
                    parser->value = rotl32(parser->value ^ lower_alpha(ch), 5u);
                    break;
                case CC_QUOTE:
                    parser->state = ST_QUOTE;
                    break;
                case CC_OPEN:
                    parser->depth++;
                    parser->state = ST_ARRAY;
                    break;
                case CC_COMMA:
                    emit_value(parser, cls);
                    parser->state = parser->depth == 0u ? ST_SEEK : ST_ARRAY;
                    break;
                case CC_SEMI:
                case CC_CLOSE:
                    emit_value(parser, cls);
                    if (cls == CC_CLOSE && parser->depth != 0u) {
                        parser->depth--;
                    }
                    parser->state = ST_SEEK;
                    break;
                default:
                    parser->hash ^= mix32(ch + parser->value);
                    break;
            }
            break;

        case ST_ARRAY:
            switch (cls) {
                case CC_DIGIT:
                    parser->value = parser->value * 10u + (ch - '0') + parser->depth;
                    parser->state = ST_VALUE;
                    break;
                case CC_SIGN:
                    parser->sign ^= (ch == '-') ? 1u : 0u;
                    parser->state = ST_VALUE;
                    break;
                case CC_ALPHA:
                    parser->key = parser->key * 17u + lower_alpha(ch) + parser->depth;
                    break;
                case CC_EQ:
                    parser->state = ST_VALUE;
                    break;
                case CC_OPEN:
                    parser->depth++;
                    parser->hash += mix32(ch ^ parser->depth);
                    break;
                case CC_CLOSE:
                    emit_value(parser, cls);
                    if (parser->depth != 0u) {
                        parser->depth--;
                    }
                    parser->state = parser->depth == 0u ? ST_SEEK : ST_ARRAY;
                    break;
                case CC_COMMA:
                case CC_SEMI:
                    emit_value(parser, cls);
                    parser->state = cls == CC_SEMI ? ST_SEEK : ST_ARRAY;
                    break;
                case CC_QUOTE:
                    parser->state = ST_QUOTE;
                    break;
                default:
                    parser->hash += cls + parser->depth;
                    break;
            }
            break;

        case ST_QUOTE:
            switch (cls) {
                case CC_QUOTE:
                    emit_value(parser, cls);
                    parser->state = parser->depth == 0u ? ST_SEEK : ST_ARRAY;
                    break;
                default:
                    parser->value = rotl32(parser->value + ch + parser->key, 3u);
                    parser->hash ^= mix32(ch + parser->value + parser->depth);
                    break;
            }
            break;

        default:
            switch (cls) {
                case CC_SEMI:
                case CC_COMMA:
                    parser->state = ST_SEEK;
                    parser->value = 0u;
                    parser->sign = 0u;
                    break;
                case CC_ALPHA:
                    parser->key = lower_alpha(ch);
                    parser->state = ST_KEY;
                    break;
                default:
                    parser->hash += mix32(ch ^ cls);
                    break;
            }
            break;
    }

    if (((parser->hash ^ parser->lanes[(pos + cls) & 7u]) & 15u) == 7u) {
        parser->state = (parser->state + ST_VALUE + cls) % (ST_SKIP + 1u);
    }
}

__attribute__((noinline))
static uint64_t parse_duff(const unsigned char *text, size_t len, uint32_t seed) {
    Parser parser;
    uint64_t result;

    parser.base = text;
    parser.cursor = text;
    parser.end = text + len;
    parser.hash = mix32(seed ^ (uint32_t)len);
    parser.key = 0u;
    parser.value = 0u;
    parser.items = 0u;
    parser.depth = 0u;
    parser.state = ST_SEEK;
    parser.sign = 0u;
    for (uint32_t i = 0u; i < 8u; ++i) {
        parser.lanes[i] = mix32(seed + i * UINT32_C(0x01010101));
    }
    for (uint32_t i = 0u; i < 64u; ++i) {
        parser.window[i] = (uint8_t)(mix32(seed ^ i) >> 24u);
    }

    if (len != 0u) {
        size_t n = (len + 7u) / 8u;

#define DUFF_STEP() do { parse_one(&parser); } while (0)
        switch (len & 7u) {
            case 0u:
                do {
                    DUFF_STEP();
                    /* fall through */
            case 7u:
                    DUFF_STEP();
                    /* fall through */
            case 6u:
                    DUFF_STEP();
                    /* fall through */
            case 5u:
                    DUFF_STEP();
                    /* fall through */
            case 4u:
                    DUFF_STEP();
                    /* fall through */
            case 3u:
                    DUFF_STEP();
                    /* fall through */
            case 2u:
                    DUFF_STEP();
                    /* fall through */
            case 1u:
                    DUFF_STEP();
                } while (--n != 0u);
        }
#undef DUFF_STEP
    }

    if (parser.value != 0u || parser.key != 0u || parser.state == ST_VALUE) {
        emit_value(&parser, UINT32_C(0xff));
    }

    result = (uint64_t)mix32(parser.hash ^ parser.items ^ parser.depth);
    for (uint32_t i = 0u; i < 8u; ++i) {
        result ^= (uint64_t)mix32(parser.lanes[i] + i) << ((i & 1u) * 32u);
        result = (result << 7u) | (result >> 57u);
    }
    for (uint32_t i = 0u; i < 64u; i += 9u) {
        result += (uint64_t)parser.window[i] * UINT64_C(0x100000001b3);
    }

    return result ^ (uint64_t)(parser.cursor == parser.end ? UINT32_C(0xa5a55a5a) : 0u);
}

int main(void) {
    static const unsigned char script0[] =
        "alpha=19;beta=[3,5,8,13];gamma=-21;zeta={q:7,r:11};omega=\"m0r0k\";";
    static const unsigned char script1[] =
        "root{left=144,right=[1,-2,3],note='fold'};tail=377;mask=(a:5,b:9);";
    static const unsigned char script2[] =
        "mix=42;maze=[north=6,east=10,south=-4,west=2];quote=\"duff/device\";end=1;";
    uint64_t checksum = UINT64_C(0x6a09e667f3bcc909);

    checksum ^= parse_duff(script0, sizeof(script0) - 1u, UINT32_C(0x10203040));
    checksum = (checksum << 11u) | (checksum >> 53u);
    checksum ^= parse_duff(script1, sizeof(script1) - 1u, (uint32_t)checksum);
    checksum = (checksum << 17u) | (checksum >> 47u);
    checksum ^= parse_duff(script2, sizeof(script2) - 1u, (uint32_t)(checksum >> 32u));

    cf_duff_device_parser_sink = checksum;
    printf("cf_duff_device_parser %016" PRIx64 "\n", cf_duff_device_parser_sink);
    return 0;
}
