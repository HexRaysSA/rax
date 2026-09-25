/*
 * SIMD AES Encryption
 *
 * AES-128 encryption using hardware AES instructions.
 * Falls back to table-based implementation when unavailable.
 *
 * Features exercised:
 *   x86:    AES-NI (aesenc, aesenclast, aeskeygenassist)
 *   ARM:    ARMv8 Crypto (aese, aesmc)
 */

#include <stdint.h>
#include <string.h>
#include <inttypes.h> /* rax: print the result so that runs can be compared */
#include <stdio.h>

#if defined(__x86_64__) || defined(__i386__)
#if defined(__AES__)
#include <wmmintrin.h>
#define HAS_AES_NI 1
#endif
#endif

#if defined(__aarch64__) && defined(__ARM_FEATURE_CRYPTO)
#include <arm_neon.h>
#define HAS_ARM_CRYPTO 1
#endif

#define BLOCK_SIZE 16
#define NUM_ROUNDS 10
#define NUM_BLOCKS 32 /* rax: was 64 */

volatile uint8_t sink;

static uint8_t plaintext[NUM_BLOCKS * BLOCK_SIZE];
static uint8_t ciphertext[NUM_BLOCKS * BLOCK_SIZE];
static uint8_t key[BLOCK_SIZE] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};

/* S-box for software implementation */
static const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
    0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
    0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
    0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
    0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
    0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
    0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
    0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
    0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
    0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static const uint8_t rcon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

/* GF(2^8) multiplication */
static uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        uint8_t hi = a & 0x80;
        a <<= 1;
        if (hi) a ^= 0x1b;
        b >>= 1;
    }
    return p;
}

/* Software AES key expansion */
static void key_expansion_soft(const uint8_t *key, uint8_t round_keys[11][16]) {
    memcpy(round_keys[0], key, 16);

    for (int i = 1; i <= 10; i++) {
        uint8_t temp[4];
        memcpy(temp, &round_keys[i-1][12], 4);

        /* RotWord */
        uint8_t t = temp[0];
        temp[0] = temp[1];
        temp[1] = temp[2];
        temp[2] = temp[3];
        temp[3] = t;

        /* SubWord */
        for (int j = 0; j < 4; j++) {
            temp[j] = sbox[temp[j]];
        }

        /* XOR with Rcon */
        temp[0] ^= rcon[i];

        for (int j = 0; j < 16; j++) {
            round_keys[i][j] = round_keys[i-1][j] ^ temp[j % 4];
            if (j % 4 == 3) {
                memcpy(temp, &round_keys[i][j-3], 4);
            }
        }
    }
}

/* Software AES encryption */
static void aes_encrypt_soft(const uint8_t *in, uint8_t *out,
                             const uint8_t round_keys[11][16]) {
    uint8_t state[16];
    memcpy(state, in, 16);

    /* Initial round key addition */
    for (int i = 0; i < 16; i++) {
        state[i] ^= round_keys[0][i];
    }

    /* Main rounds */
    for (int round = 1; round < 10; round++) {
        /* SubBytes */
        for (int i = 0; i < 16; i++) {
            state[i] = sbox[state[i]];
        }

        /* ShiftRows */
        uint8_t temp;
        temp = state[1]; state[1] = state[5]; state[5] = state[9];
        state[9] = state[13]; state[13] = temp;
        temp = state[2]; state[2] = state[10]; state[10] = temp;
        temp = state[6]; state[6] = state[14]; state[14] = temp;
        temp = state[15]; state[15] = state[11]; state[11] = state[7];
        state[7] = state[3]; state[3] = temp;

        /* MixColumns */
        for (int col = 0; col < 4; col++) {
            uint8_t *c = &state[col * 4];
            uint8_t a0 = c[0], a1 = c[1], a2 = c[2], a3 = c[3];
            c[0] = gmul(a0, 2) ^ gmul(a1, 3) ^ a2 ^ a3;
            c[1] = a0 ^ gmul(a1, 2) ^ gmul(a2, 3) ^ a3;
            c[2] = a0 ^ a1 ^ gmul(a2, 2) ^ gmul(a3, 3);
            c[3] = gmul(a0, 3) ^ a1 ^ a2 ^ gmul(a3, 2);
        }

        /* AddRoundKey */
        for (int i = 0; i < 16; i++) {
            state[i] ^= round_keys[round][i];
        }
    }

    /* Final round (no MixColumns) */
    for (int i = 0; i < 16; i++) {
        state[i] = sbox[state[i]];
    }
    uint8_t temp;
    temp = state[1]; state[1] = state[5]; state[5] = state[9];
    state[9] = state[13]; state[13] = temp;
    temp = state[2]; state[2] = state[10]; state[10] = temp;
    temp = state[6]; state[6] = state[14]; state[14] = temp;
    temp = state[15]; state[15] = state[11]; state[11] = state[7];
    state[7] = state[3]; state[3] = temp;
    for (int i = 0; i < 16; i++) {
        state[i] ^= round_keys[10][i];
    }

    memcpy(out, state, 16);
}

#if defined(HAS_AES_NI)
/* AES-NI key expansion */
static inline __m128i aes_128_key_expansion(__m128i key, __m128i keygen) {
    keygen = _mm_shuffle_epi32(keygen, _MM_SHUFFLE(3, 3, 3, 3));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    return _mm_xor_si128(key, keygen);
}

static void aes_encrypt_aesni(const uint8_t *in, uint8_t *out,
                               const uint8_t *key_bytes) {
    __m128i key_schedule[11];
    __m128i key = _mm_loadu_si128((const __m128i *)key_bytes);
    key_schedule[0] = key;

    key_schedule[1] = aes_128_key_expansion(key_schedule[0],
        _mm_aeskeygenassist_si128(key_schedule[0], 0x01));
    key_schedule[2] = aes_128_key_expansion(key_schedule[1],
        _mm_aeskeygenassist_si128(key_schedule[1], 0x02));
    key_schedule[3] = aes_128_key_expansion(key_schedule[2],
        _mm_aeskeygenassist_si128(key_schedule[2], 0x04));
    key_schedule[4] = aes_128_key_expansion(key_schedule[3],
        _mm_aeskeygenassist_si128(key_schedule[3], 0x08));
    key_schedule[5] = aes_128_key_expansion(key_schedule[4],
        _mm_aeskeygenassist_si128(key_schedule[4], 0x10));
    key_schedule[6] = aes_128_key_expansion(key_schedule[5],
        _mm_aeskeygenassist_si128(key_schedule[5], 0x20));
    key_schedule[7] = aes_128_key_expansion(key_schedule[6],
        _mm_aeskeygenassist_si128(key_schedule[6], 0x40));
    key_schedule[8] = aes_128_key_expansion(key_schedule[7],
        _mm_aeskeygenassist_si128(key_schedule[7], 0x80));
    key_schedule[9] = aes_128_key_expansion(key_schedule[8],
        _mm_aeskeygenassist_si128(key_schedule[8], 0x1b));
    key_schedule[10] = aes_128_key_expansion(key_schedule[9],
        _mm_aeskeygenassist_si128(key_schedule[9], 0x36));

    __m128i state = _mm_loadu_si128((const __m128i *)in);
    state = _mm_xor_si128(state, key_schedule[0]);
    state = _mm_aesenc_si128(state, key_schedule[1]);
    state = _mm_aesenc_si128(state, key_schedule[2]);
    state = _mm_aesenc_si128(state, key_schedule[3]);
    state = _mm_aesenc_si128(state, key_schedule[4]);
    state = _mm_aesenc_si128(state, key_schedule[5]);
    state = _mm_aesenc_si128(state, key_schedule[6]);
    state = _mm_aesenc_si128(state, key_schedule[7]);
    state = _mm_aesenc_si128(state, key_schedule[8]);
    state = _mm_aesenc_si128(state, key_schedule[9]);
    state = _mm_aesenclast_si128(state, key_schedule[10]);

    _mm_storeu_si128((__m128i *)out, state);
}
#endif

#if defined(HAS_ARM_CRYPTO)
static void aes_encrypt_arm(const uint8_t *in, uint8_t *out,
                            const uint8_t round_keys[11][16]) {
    uint8x16_t state = vld1q_u8(in);

    state = vaesmcq_u8(vaeseq_u8(state, vld1q_u8(round_keys[0])));
    state = vaesmcq_u8(vaeseq_u8(state, vld1q_u8(round_keys[1])));
    state = vaesmcq_u8(vaeseq_u8(state, vld1q_u8(round_keys[2])));
    state = vaesmcq_u8(vaeseq_u8(state, vld1q_u8(round_keys[3])));
    state = vaesmcq_u8(vaeseq_u8(state, vld1q_u8(round_keys[4])));
    state = vaesmcq_u8(vaeseq_u8(state, vld1q_u8(round_keys[5])));
    state = vaesmcq_u8(vaeseq_u8(state, vld1q_u8(round_keys[6])));
    state = vaesmcq_u8(vaeseq_u8(state, vld1q_u8(round_keys[7])));
    state = vaesmcq_u8(vaeseq_u8(state, vld1q_u8(round_keys[8])));
    state = vaeseq_u8(state, vld1q_u8(round_keys[9]));
    state = veorq_u8(state, vld1q_u8(round_keys[10]));

    vst1q_u8(out, state);
}
#endif

int main(void) {
    /* Initialize plaintext */
    for (int i = 0; i < NUM_BLOCKS * BLOCK_SIZE; i++) {
        plaintext[i] = (uint8_t)(i & 0xFF);
    }

    /* Expand key for software implementation */
    uint8_t round_keys[11][16];
    key_expansion_soft(key, round_keys);

    for (int iter = 0; iter < 2; iter++) { /* rax: was 1000 */
        for (int block = 0; block < NUM_BLOCKS; block++) {
            uint8_t *in_block = &plaintext[block * BLOCK_SIZE];
            uint8_t *out_block = &ciphertext[block * BLOCK_SIZE];

#if defined(HAS_AES_NI)
            aes_encrypt_aesni(in_block, out_block, key);
#elif defined(HAS_ARM_CRYPTO)
            aes_encrypt_arm(in_block, out_block, round_keys);
#else
            aes_encrypt_soft(in_block, out_block, round_keys);
#endif
        }

        /* Use output as next input */
        memcpy(plaintext, ciphertext, NUM_BLOCKS * BLOCK_SIZE);
    }

    /* Prevent optimization */
    uint8_t sum = 0;
    for (int i = 0; i < NUM_BLOCKS * BLOCK_SIZE; i++) {
        sum ^= ciphertext[i];
    }
    sink = sum;

    uint64_t ciphertext_digest = UINT64_C(0xcbf29ce484222325); /* rax: print the result so that runs can be compared */
    for (int i = 0; i < NUM_BLOCKS * BLOCK_SIZE; i++) {
        ciphertext_digest = (ciphertext_digest ^ ciphertext[i]) * UINT64_C(0x100000001b3);
    }
    printf("sum=%u\n", (unsigned)sum);
    printf("ciphertext_digest=%016" PRIx64 "\n", ciphertext_digest);
    printf("block0=");
    for (int i = 0; i < BLOCK_SIZE; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");
    return 0;
}
