/*
 * Sparse Switch Statement (Binary Search)
 *
 * Switches with non-consecutive case values generate comparison trees.
 * Tests conditional branching patterns.
 *
 * Features exercised:
 *   - Binary search dispatch
 *   - Conditional branch sequences
 *   - Range checking
 */

#include <stdint.h>
#include <inttypes.h> /* rax: print the result so that runs can be compared */
#include <stdio.h>

volatile int64_t sink;

/* Very sparse cases - will use comparisons */
__attribute__((noinline))
int sparse_switch(int x) {
    switch (x) {
        case 1: return 100;
        case 10: return 200;
        case 100: return 300;
        case 1000: return 400;
        case 10000: return 500;
        case 100000: return 600;
        case 1000000: return 700;
        default: return 0;
    }
}

/* Power of 2 cases - also sparse */
__attribute__((noinline))
int sparse_powers(int x) {
    switch (x) {
        case 1: return 0;
        case 2: return 1;
        case 4: return 2;
        case 8: return 3;
        case 16: return 4;
        case 32: return 5;
        case 64: return 6;
        case 128: return 7;
        case 256: return 8;
        case 512: return 9;
        case 1024: return 10;
        case 2048: return 11;
        case 4096: return 12;
        case 8192: return 13;
        case 16384: return 14;
        case 32768: return 15;
        default: return -1;
    }
}

/* HTTP status codes - real-world sparse pattern */
__attribute__((noinline))
int http_status_category(int code) {
    switch (code) {
        case 200: return 1; /* OK */
        case 201: return 1; /* Created */
        case 204: return 1; /* No Content */
        case 301: return 2; /* Moved Permanently */
        case 302: return 2; /* Found */
        case 304: return 2; /* Not Modified */
        case 400: return 3; /* Bad Request */
        case 401: return 3; /* Unauthorized */
        case 403: return 3; /* Forbidden */
        case 404: return 3; /* Not Found */
        case 405: return 3; /* Method Not Allowed */
        case 500: return 4; /* Internal Server Error */
        case 501: return 4; /* Not Implemented */
        case 502: return 4; /* Bad Gateway */
        case 503: return 4; /* Service Unavailable */
        default: return 0;
    }
}

/* Negative and positive sparse values */
__attribute__((noinline))
int sparse_negative(int x) {
    switch (x) {
        case -1000000: return -6;
        case -10000: return -5;
        case -1000: return -4;
        case -100: return -3;
        case -10: return -2;
        case -1: return -1;
        case 0: return 0;
        case 1: return 1;
        case 10: return 2;
        case 100: return 3;
        case 1000: return 4;
        case 10000: return 5;
        case 1000000: return 6;
        default: return 99;
    }
}

/* Prime numbers - irregular spacing */
__attribute__((noinline))
int is_small_prime(int x) {
    switch (x) {
        case 2: case 3: case 5: case 7: case 11:
        case 13: case 17: case 19: case 23: case 29:
        case 31: case 37: case 41: case 43: case 47:
        case 53: case 59: case 61: case 67: case 71:
        case 73: case 79: case 83: case 89: case 97:
            return 1;
        default:
            return 0;
    }
}

/* Unicode codepoint ranges - wide gaps */
__attribute__((noinline))
int unicode_block(int codepoint) {
    switch (codepoint) {
        case 0x0000 ... 0x007F: return 1;  /* Basic Latin */
        case 0x0080 ... 0x00FF: return 2;  /* Latin-1 Supplement */
        case 0x0100 ... 0x017F: return 3;  /* Latin Extended-A */
        case 0x0400 ... 0x04FF: return 4;  /* Cyrillic */
        case 0x0600 ... 0x06FF: return 5;  /* Arabic */
        case 0x3040 ... 0x309F: return 6;  /* Hiragana */
        case 0x30A0 ... 0x30FF: return 7;  /* Katakana */
        case 0x4E00 ... 0x9FFF: return 8;  /* CJK Unified */
        case 0x1F600 ... 0x1F64F: return 9;  /* Emoticons */
        default: return 0;
    }
}

/* Mixed dense/sparse regions */
__attribute__((noinline))
int mixed_density(int x) {
    switch (x) {
        /* Dense region 0-7 */
        case 0: return 1000;
        case 1: return 1001;
        case 2: return 1002;
        case 3: return 1003;
        case 4: return 1004;
        case 5: return 1005;
        case 6: return 1006;
        case 7: return 1007;
        /* Sparse region */
        case 100: return 2000;
        case 200: return 2001;
        case 300: return 2002;
        /* Dense region 1000-1007 */
        case 1000: return 3000;
        case 1001: return 3001;
        case 1002: return 3002;
        case 1003: return 3003;
        case 1004: return 3004;
        case 1005: return 3005;
        case 1006: return 3006;
        case 1007: return 3007;
        default: return 0;
    }
}

/* Bit pattern matching */
__attribute__((noinline))
int bit_pattern(unsigned int x) {
    switch (x) {
        case 0x00000000: return 0;
        case 0x0000FFFF: return 1;
        case 0xFFFF0000: return 2;
        case 0xFFFFFFFF: return 3;
        case 0x55555555: return 4;
        case 0xAAAAAAAA: return 5;
        case 0x0F0F0F0F: return 6;
        case 0xF0F0F0F0: return 7;
        case 0x00FF00FF: return 8;
        case 0xFF00FF00: return 9;
        case 0x12345678: return 10;
        case 0xDEADBEEF: return 11;
        case 0xCAFEBABE: return 12;
        default: return -1;
    }
}

int main(void) {
    int64_t result = 0;

    for (int i = 0; i < 1200; i++) { /* rax: was 100000 */
        /* Test sparse values */
        int vals[] = {1, 10, 100, 1000, 10000, 42, 999};
        result += sparse_switch(vals[i % 7]);

        /* Test powers of 2 */
        result += sparse_powers(1 << (i % 16));

        /* Test HTTP codes */
        int codes[] = {200, 201, 301, 404, 500, 418, 302};
        result += http_status_category(codes[i % 7]);

        /* Test negative values */
        result += sparse_negative(i % 2 == 0 ? i : -i);

        /* Test prime check */
        result += is_small_prime(i % 100);

        /* Test unicode blocks */
        int codepoints[] = {65, 0x100, 0x400, 0x3040, 0x4E00, 0x1F600};
        result += unicode_block(codepoints[i % 6]);

        /* Test mixed density */
        int mixed[] = {0, 3, 7, 100, 200, 1000, 1005, 50};
        result += mixed_density(mixed[i % 8]);

        /* Test bit patterns */
        unsigned int patterns[] = {0, 0xFFFFFFFF, 0x55555555, 0xDEADBEEF, 0x12345678};
        result += bit_pattern(patterns[i % 5]);
    }

    sink = result;
    printf("sink=%" PRId64 "\n", sink); /* rax: print the result so that runs can be compared */
    return 0;
}
