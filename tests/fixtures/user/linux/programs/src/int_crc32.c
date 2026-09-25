/*
 * CRC32 Implementation
 *
 * Multiple CRC32 implementations:
 * - Table-based (standard)
 * - Byte-at-a-time
 * - Slice-by-4 (faster)
 *
 * Features exercised:
 *   - XOR operations
 *   - Table lookups
 *   - Shift operations
 */

#include <stdint.h>
#include <stddef.h>
#include <stdio.h> /* rax: print the result so that runs can be compared */

#define DATA_SIZE 4096

volatile uint32_t sink;

static uint8_t data[DATA_SIZE];

/* CRC32 polynomial (IEEE 802.3) */
#define CRC32_POLY 0xEDB88320

/* Pre-computed CRC table */
static uint32_t crc_table[256];
static uint32_t crc_table_slice[4][256];
static int tables_initialized = 0;

/* Generate CRC lookup table */
static void init_crc_table(void) {
    if (tables_initialized) return;

    for (uint32_t i = 0; i < 256; i++) {
        uint32_t crc = i;
        for (int j = 0; j < 8; j++) {
            if (crc & 1) {
                crc = (crc >> 1) ^ CRC32_POLY;
            } else {
                crc = crc >> 1;
            }
        }
        crc_table[i] = crc;
    }

    /* Generate slice-by-4 tables */
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t crc = crc_table[i];
        crc_table_slice[0][i] = crc;
        for (int j = 1; j < 4; j++) {
            crc = (crc >> 8) ^ crc_table[crc & 0xFF];
            crc_table_slice[j][i] = crc;
        }
    }

    tables_initialized = 1;
}

/* Bit-by-bit CRC32 (slow but simple) */
static uint32_t crc32_bitwise(const uint8_t *buf, size_t len) {
    uint32_t crc = 0xFFFFFFFF;

    for (size_t i = 0; i < len; i++) {
        crc ^= buf[i];
        for (int j = 0; j < 8; j++) {
            if (crc & 1) {
                crc = (crc >> 1) ^ CRC32_POLY;
            } else {
                crc = crc >> 1;
            }
        }
    }

    return crc ^ 0xFFFFFFFF;
}

/* Table-based CRC32 (standard) */
static uint32_t crc32_table(const uint8_t *buf, size_t len) {
    uint32_t crc = 0xFFFFFFFF;

    for (size_t i = 0; i < len; i++) {
        uint8_t index = (crc ^ buf[i]) & 0xFF;
        crc = (crc >> 8) ^ crc_table[index];
    }

    return crc ^ 0xFFFFFFFF;
}

/* Slice-by-4 CRC32 (faster) */
static uint32_t crc32_slice4(const uint8_t *buf, size_t len) {
    uint32_t crc = 0xFFFFFFFF;
    const uint8_t *p = buf;

    /* Process 4 bytes at a time */
    while (len >= 4) {
        crc ^= ((uint32_t)p[0])
             | ((uint32_t)p[1] << 8)
             | ((uint32_t)p[2] << 16)
             | ((uint32_t)p[3] << 24);

        crc = crc_table_slice[3][crc & 0xFF]
            ^ crc_table_slice[2][(crc >> 8) & 0xFF]
            ^ crc_table_slice[1][(crc >> 16) & 0xFF]
            ^ crc_table_slice[0][(crc >> 24) & 0xFF];

        p += 4;
        len -= 4;
    }

    /* Process remaining bytes */
    while (len--) {
        crc = (crc >> 8) ^ crc_table[(crc ^ *p++) & 0xFF];
    }

    return crc ^ 0xFFFFFFFF;
}

/* CRC32C polynomial (used in iSCSI, ext4) */
#define CRC32C_POLY 0x82F63B78

static uint32_t crc32c_table[256];

static void init_crc32c_table(void) {
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t crc = i;
        for (int j = 0; j < 8; j++) {
            if (crc & 1) {
                crc = (crc >> 1) ^ CRC32C_POLY;
            } else {
                crc = crc >> 1;
            }
        }
        crc32c_table[i] = crc;
    }
}

static uint32_t crc32c(const uint8_t *buf, size_t len) {
    uint32_t crc = 0xFFFFFFFF;

    for (size_t i = 0; i < len; i++) {
        crc = (crc >> 8) ^ crc32c_table[(crc ^ buf[i]) & 0xFF];
    }

    return crc ^ 0xFFFFFFFF;
}

/* Combined CRC (for testing) */
static uint32_t combined_crc(const uint8_t *buf, size_t len) {
    uint32_t crc1 = crc32_table(buf, len);
    uint32_t crc2 = crc32c(buf, len);
    return crc1 ^ crc2;
}

int main(void) {
    /* Initialize tables */
    init_crc_table();
    init_crc32c_table();

    /* Initialize test data */
    for (int i = 0; i < DATA_SIZE; i++) {
        data[i] = (uint8_t)((i * 17 + 31) % 256);
    }

    uint32_t checksum = 0;

    for (int iter = 0; iter < 1000; iter += 71) { /* rax: was iter++ */
        size_t len = (iter % DATA_SIZE) + 1;

        /* Test different implementations */
        uint32_t crc1, crc2, crc3, crc4;

        /* Table-based */
        crc1 = crc32_table(data, len);
        checksum ^= crc1;

        /* Slice-by-4 */
        crc2 = crc32_slice4(data, len);
        checksum ^= crc2;

        /* CRC32C variant */
        crc3 = crc32c(data, len);
        checksum ^= crc3;

        /* Combined */
        crc4 = combined_crc(data, len);
        checksum ^= crc4;

        /* Bitwise (only on small data for speed) */
        if (len < 256) {
            uint32_t crc5 = crc32_bitwise(data, len);
            checksum ^= crc5;
        }

        /* Modify data based on CRC */
        data[iter % DATA_SIZE] ^= (uint8_t)(crc1 & 0xFF);
    }

    sink = checksum;
    printf("sink=%08x\n", (unsigned)sink); /* rax: print the result so that runs can be compared */
    return 0;
}
