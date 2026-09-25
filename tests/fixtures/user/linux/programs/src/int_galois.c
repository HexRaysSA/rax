/*
 * Galois Field (GF(2^8)) Operations
 *
 * Operations used in Reed-Solomon codes and AES.
 * Heavy use of XOR, shifts, and table lookups.
 *
 * Features exercised:
 *   - XOR operations
 *   - Conditional execution (carry-less multiply)
 *   - Table-based lookup
 */

#include <stdint.h>
#include <stdio.h> /* rax: print the result so that runs can be compared */

#define GF_SIZE 256
#define DATA_SIZE 255  /* RS codeword size */

volatile uint8_t sink;

/* GF(2^8) with polynomial x^8 + x^4 + x^3 + x^2 + 1 (0x11D) */
#define GF_POLY 0x11D

/* Lookup tables for GF operations */
static uint8_t gf_exp[512];  /* exp[i] = alpha^i */
static uint8_t gf_log[256];  /* log[i] = discrete log of i */
static uint8_t gf_mul_table[256][256];

static int tables_initialized = 0;

/* GF multiply without table - bitwise */
static uint8_t gf_mul_bitwise(uint8_t a, uint8_t b) {
    uint8_t result = 0;

    while (b) {
        if (b & 1) {
            result ^= a;
        }
        b >>= 1;

        /* Multiply a by x (shift and reduce) */
        if (a & 0x80) {
            a = (a << 1) ^ (GF_POLY & 0xFF);
        } else {
            a <<= 1;
        }
    }

    return result;
}

/* Initialize GF tables */
static void gf_init(void) {
    if (tables_initialized) return;

    /* Generate exp and log tables using generator alpha = 2 */
    uint16_t x = 1;
    for (int i = 0; i < 255; i++) {
        gf_exp[i] = (uint8_t)x;
        gf_log[(uint8_t)x] = (uint8_t)i;

        /* x = x * alpha, with reduction */
        x <<= 1;
        if (x & 0x100) {
            x ^= GF_POLY;
        }
    }

    /* Extend exp table for easy modular arithmetic */
    for (int i = 255; i < 512; i++) {
        gf_exp[i] = gf_exp[i - 255];
    }

    gf_log[0] = 0;  /* Convention: log(0) = 0, but 0 needs special handling */

    /* Pre-compute multiplication table */
    for (int i = 0; i < 64; i++) { /* rax: was 256 */
        for (int j = 0; j < 64; j++) { /* rax: was 256 */
            gf_mul_table[i][j] = gf_mul_bitwise((uint8_t)i, (uint8_t)j);
        }
    }

    tables_initialized = 1;
}

/* GF multiply using log/exp tables */
static inline uint8_t gf_mul_log(uint8_t a, uint8_t b) {
    if (a == 0 || b == 0) return 0;
    int log_sum = gf_log[a] + gf_log[b];
    return gf_exp[log_sum];  /* exp table extended, so no need for mod */
}

/* GF multiply using precomputed table */
static inline uint8_t gf_mul_table_lookup(uint8_t a, uint8_t b) {
    return gf_mul_table[a][b];
}

/* GF inverse */
static inline uint8_t gf_inv(uint8_t a) {
    if (a == 0) return 0;  /* Error, but handle gracefully */
    return gf_exp[255 - gf_log[a]];
}

/* GF division */
static inline uint8_t gf_div(uint8_t a, uint8_t b) {
    if (b == 0) return 0;  /* Error */
    if (a == 0) return 0;
    int log_diff = gf_log[a] - gf_log[b];
    if (log_diff < 0) log_diff += 255;
    return gf_exp[log_diff];
}

/* GF power */
static uint8_t gf_pow(uint8_t a, int n) {
    if (a == 0) return 0;
    if (n == 0) return 1;
    int log_prod = (gf_log[a] * n) % 255;
    return gf_exp[log_prod];
}

/* Polynomial evaluation at a point in GF */
static uint8_t poly_eval(const uint8_t *poly, int degree, uint8_t x) {
    uint8_t result = poly[0];
    uint8_t x_pow = 1;

    for (int i = 1; i <= degree; i++) {
        x_pow = gf_mul_log(x_pow, x);
        result ^= gf_mul_log(poly[i], x_pow);
    }

    return result;
}

/* Reed-Solomon encoding (simplified) */
static void rs_encode(const uint8_t *data, int data_len,
                      uint8_t *parity, int parity_len) {
    /* Generator polynomial coefficients (simplified) */
    uint8_t gen[17];  /* Up to 16 parity symbols */

    /* Build generator polynomial: (x - alpha^0)(x - alpha^1)...(x - alpha^(n-1)) */
    gen[0] = 1;
    for (int i = 0; i < parity_len; i++) {
        gen[i + 1] = 0;
        uint8_t root = gf_exp[i];
        for (int j = i + 1; j > 0; j--) {
            gen[j] = gen[j - 1] ^ gf_mul_log(gen[j], root);
        }
        gen[0] = gf_mul_log(gen[0], root);
    }

    /* Initialize parity */
    for (int i = 0; i < parity_len; i++) {
        parity[i] = 0;
    }

    /* Compute parity using synthetic division */
    for (int i = 0; i < data_len; i++) {
        uint8_t coef = data[i] ^ parity[0];

        /* Shift parity register */
        for (int j = 0; j < parity_len - 1; j++) {
            parity[j] = parity[j + 1] ^ gf_mul_log(coef, gen[parity_len - 1 - j]);
        }
        parity[parity_len - 1] = gf_mul_log(coef, gen[0]);
    }
}

/* Compute syndrome */
static void rs_syndrome(const uint8_t *codeword, int len,
                        uint8_t *syndrome, int nsym) {
    for (int i = 0; i < nsym; i++) {
        uint8_t root = gf_exp[i];
        syndrome[i] = poly_eval(codeword, len - 1, root);
    }
}

int main(void) {
    gf_init();

    uint8_t data[DATA_SIZE];
    uint8_t parity[16];
    uint8_t syndrome[16];
    uint8_t checksum = 0;

    /* Initialize test data */
    for (int i = 0; i < DATA_SIZE; i++) {
        data[i] = (uint8_t)((i * 17 + 31) % 256);
    }

    for (int iter = 0; iter < 10; iter++) { /* rax: was 1000 */
        /* Test GF operations */
        uint8_t a = (uint8_t)((iter * 13) % 256);
        uint8_t b = (uint8_t)((iter * 17 + 7) % 256);

        /* Multiplication methods */
        uint8_t m1 = gf_mul_bitwise(a, b);
        uint8_t m2 = gf_mul_log(a, b);
        uint8_t m3 = gf_mul_table_lookup(a, b);

        checksum ^= m1 ^ m2 ^ m3;

        /* Inverse and division */
        if (a != 0) {
            uint8_t inv = gf_inv(a);
            uint8_t check = gf_mul_log(a, inv);  /* Should be 1 */
            checksum ^= inv ^ check;
        }

        if (b != 0) {
            uint8_t d = gf_div(a, b);
            uint8_t check = gf_mul_log(d, b);  /* Should be a */
            checksum ^= d ^ check;
        }

        /* Power */
        uint8_t p = gf_pow(a, iter % 32);
        checksum ^= p;

        /* RS encoding (every 10th iteration) */
        if (iter % 10 == 0) {
            /* Modify data slightly */
            data[iter % DATA_SIZE] ^= (uint8_t)(iter & 0xFF);

            /* Encode */
            rs_encode(data, DATA_SIZE - 16, parity, 16);

            /* Accumulate parity */
            for (int i = 0; i < 16; i++) {
                checksum ^= parity[i];
            }

            /* Compute syndrome (should be all zeros for valid codeword) */
            uint8_t codeword[DATA_SIZE];
            for (int i = 0; i < DATA_SIZE - 16; i++) {
                codeword[i] = data[i];
            }
            for (int i = 0; i < 16; i++) {
                codeword[DATA_SIZE - 16 + i] = parity[i];
            }

            rs_syndrome(codeword, DATA_SIZE, syndrome, 16);
            for (int i = 0; i < 16; i++) {
                checksum ^= syndrome[i];
            }
        }
    }

    sink = checksum;
    printf("sink=%02x\n", (unsigned)sink); /* rax: print the result so that runs can be compared */
    return 0;
}
