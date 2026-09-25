#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>

#define HASH_CODE_1 0x82E1
#define HASH_CODE_2 0x8325
#define TARGET_HASH 0xA5B6

static uint16_t hasher(uint16_t hash, uint8_t byte, uint16_t code) {
    for (int i = 0; i < 8; i++, byte >>= 1) {
        uint16_t bit = byte & 1;
        if (hash % 2 == bit)
            hash >>= 1;
        else
            hash = (hash >> 1) ^ code;
    }
    return hash;
}

static uint16_t encoding_hash(uint16_t n1) {
    uint32_t d = (uint32_t)floor(n1 * 99999.0 / 0xFFFF);
    uint32_t lo2 = d % 100;
    d -= lo2;
    uint32_t mid = d % 1000;
    d -= mid;
    d += lo2 * 10 + mid / 100;
    uint16_t temp = (uint16_t)ceil(d * 65535.0 / 99999.0);
    return hasher(hasher(0, temp & 0xFF, HASH_CODE_2), temp >> 8, HASH_CODE_2);
}

static uint16_t find_magic_char(uint16_t code, uint16_t hash) {
    for (uint16_t c1 = 0; c1 < 256; c1++) {
        for (uint16_t c2 = 0; c2 < 256; c2++) {
            if (hasher(hasher(hash, (uint8_t)c1, code), (uint8_t)c2, code) == TARGET_HASH)
                return (uint16_t)(c1 | (c2 << 8));
        }
    }
    return 0xFFFF;
}

static uint16_t encoding_characters(uint16_t code, uint16_t hash,
                                    const uint8_t *chars, size_t len) {
    for (size_t i = 0; i < len; i++)
        hash = hasher(hash, chars[i], code);
    return find_magic_char(code, hash);
}

static int check_format(const char *fmt, const char *s) {
    if (strlen(fmt) != strlen(s)) return 0;
    for (size_t i = 0; fmt[i]; i++) {
        if (fmt[i] == 'x') {
            if (s[i] < '0' || s[i] > '9') return 0;
        } else if (fmt[i] == 'a') {
            if (s[i] < 'A' || s[i] > 'Z') return 0;
        } else if (fmt[i] == 'b') {
            if ((s[i] < '0' || s[i] > '9') && (s[i] < 'A' || s[i] > 'Z'))
                return 0;
        } else {
            if (fmt[i] != s[i]) return 0;
        }
    }
    return 1;
}

static void split_hex(uint16_t hex, uint8_t digits[5]) {
    uint32_t n = (uint32_t)floor(hex * 99999.0 / 0xFFFF);
    for (int i = 0; i < 5; i++) {
        digits[i] = n % 10;
        n /= 10;
    }
}

static void construct_password(uint16_t n1, uint16_t n2, char *out) {
    uint8_t d1[5], d2[5];
    split_hex(n1, d1);
    split_hex(n2, d2);
    snprintf(out, 13, "%u%u%u%u-%u%u%u-%u%u%u",
             d2[1], d1[1], d1[3], d1[4],
             d2[0], d1[2], d2[4],
             d2[2], d1[0], d2[3]);
}

__attribute__((unused))
static int extract_password(const char *pass, uint16_t *n1, uint16_t *n2) {
    if (strlen(pass) != 12) return -1;
    uint32_t v1 = (uint32_t)(pass[3] - '0') * 10000
                + (uint32_t)(pass[2] - '0') * 1000
                + (uint32_t)(pass[6] - '0') * 100
                + (uint32_t)(pass[1] - '0') * 10
                + (uint32_t)(pass[10] - '0');
    uint32_t v2 = (uint32_t)(pass[7] - '0') * 10000
                + (uint32_t)(pass[11] - '0') * 1000
                + (uint32_t)(pass[9] - '0') * 100
                + (uint32_t)(pass[0] - '0') * 10
                + (uint32_t)(pass[5] - '0');
    *n1 = (uint16_t)ceil(v1 * 65535.0 / 99999.0);
    *n2 = (uint16_t)ceil(v2 * 65535.0 / 99999.0);
    return 0;
}

__attribute__((unused))
static int verify_password(uint16_t hash1, uint16_t n1, uint16_t n2,
                           const uint8_t *chars, size_t len) {
    uint16_t n0 = (uint16_t)((n1 + 0x8D06) & 0xFFFF);
    uint16_t hash2 = encoding_hash(n1);

    uint16_t h1 = hash1;
    for (size_t i = 0; i < len; i++)
        h1 = hasher(h1, chars[i], HASH_CODE_1);
    if (hasher(hasher(h1, n0 & 0xFF, HASH_CODE_1), n0 >> 8, HASH_CODE_1) != TARGET_HASH)
        return 0;

    uint16_t h2 = hash2;
    for (size_t i = 0; i < len; i++)
        h2 = hasher(h2, chars[i], HASH_CODE_2);
    if (hasher(hasher(h2, n2 & 0xFF, HASH_CODE_2), n2 >> 8, HASH_CODE_2) != TARGET_HASH)
        return 0;
    return 1;
}

static int check_math_id(const char *s) {
    return check_format("xxxx-xxxxx-xxxxx", s);
}

static void random_fill(const char *fmt, char *out) {
    for (size_t i = 0; fmt[i]; i++) {
        if (fmt[i] == 'x')
            out[i] = '0' + rand() % 10;
        else if (fmt[i] == 'a')
            out[i] = 'A' + rand() % 26;
        else if (fmt[i] == 'b')
            out[i] = (rand() % 100 < 72)
                   ? ('A' + rand() % 26)
                   : ('0' + rand() % 10);
        else
            out[i] = fmt[i];
    }
    out[strlen(fmt)] = '\0';
}

static void make_reversed_chars(const char *input, uint8_t **out, size_t *outlen) {
    size_t len = strlen(input);
    *out = malloc(len);
    *outlen = len;
    for (size_t i = 0; i < len; i++)
        (*out)[i] = (uint8_t)input[len - 1 - i];
}

static int gen_password(const char *math_id, const char *math_num,
                        const char *expire_date, const char *activation_key,
                        uint16_t hash, char *password_out) {
    char input[256];
    snprintf(input, sizeof(input), "%s@%s$%s&%s",
             math_id, expire_date, math_num, activation_key);

    uint8_t *chars;
    size_t len;
    make_reversed_chars(input, &chars, &len);

    uint16_t n0 = encoding_characters(HASH_CODE_1, hash, chars, len);
    uint16_t n1 = (uint16_t)((n0 + 0x72FA) & 0xFFFF);
    uint16_t hash2 = encoding_hash(n1);
    uint16_t n2 = encoding_characters(HASH_CODE_2, hash2, chars, len);
    free(chars);

    char pass_part[16];
    construct_password(n1, n2, pass_part);
    snprintf(password_out, 64, "%s::%s:%s", pass_part, math_num, expire_date);
    return 0;
}

static int gen_password_v14_0_0(const char *math_id, const char *math_num,
                                const char *activation_key, uint16_t hash,
                                char *password_out) {
    char input[256];
    snprintf(input, sizeof(input), "%s$%s&%s", math_id, math_num, activation_key);

    uint8_t *chars;
    size_t len;
    make_reversed_chars(input, &chars, &len);

    uint16_t n0 = encoding_characters(HASH_CODE_1, hash, chars, len);
    uint16_t n1 = (uint16_t)((n0 + 0x72FA) & 0xFFFF);
    uint16_t hash2 = encoding_hash(n1);
    uint16_t n2 = encoding_characters(HASH_CODE_2, hash2, chars, len);
    free(chars);

    char pass_part[16];
    construct_password(n1, n2, pass_part);
    snprintf(password_out, 64, "%s::%s", pass_part, math_num);
    return 0;
}

static void get_date_after(int days, char *out) {
    time_t t = time(NULL);
    struct tm *tm = localtime(&t);
    tm->tm_mday += days;
    mktime(tm);
    strftime(out, 9, "%Y%m%d", tm);
}

static const uint16_t magic_list[] = { 24816, 59222 };

int main(void) {
    srand((unsigned)time(NULL));

    printf("Version:\n");
    printf("  1) >= v14.1.0\n");
    printf("  2) <= v14.0.0\n");
    printf("> ");
    fflush(stdout);

    int ver = 0;
    if (scanf("%d", &ver) != 1 || ver < 1 || ver > 2) {
        fprintf(stderr, "Bad choice\n");
        return 1;
    }
    getchar();

    char mathId[64];
    printf("Enter MathID (xxxx-xxxxx-xxxxx): ");
    fflush(stdout);
    if (!fgets(mathId, sizeof(mathId), stdin)) return 1;
    mathId[strcspn(mathId, "\n")] = '\0';
    if (!check_math_id(mathId)) {
        printf("Bad MathID!\n");
        return 1;
    }

    char activationKey[20];
    if (ver == 1)
        random_fill("xxxx-xxxx-aaaaaa", activationKey);
    else
        random_fill("xxxx-xxxx-xxxxxx", activationKey);

    uint16_t hash = magic_list[rand() % 2];

    char mathNum[16] = "800001";
    char expireDate[16];

    if (ver == 1) {
        printf("Enter MathNum (6 chars, e.g. 800001): ");
        fflush(stdout);
        if (!fgets(mathNum, sizeof(mathNum), stdin)) return 1;
        mathNum[strcspn(mathNum, "\n")] = '\0';

        printf("Enter expiry (YYYYMMDD, or 'd' for default +999d): ");
        fflush(stdout);
        if (!fgets(expireDate, sizeof(expireDate), stdin)) return 1;
        expireDate[strcspn(expireDate, "\n")] = '\0';
        if (expireDate[0] == 'd')
            get_date_after(999, expireDate);
    } else {
        printf("Enter MathNum: ");
        fflush(stdout);
        if (!fgets(mathNum, sizeof(mathNum), stdin)) return 1;
        mathNum[strcspn(mathNum, "\n")] = '\0';
    }

    char password[80];
    int rc;
    if (ver == 1)
        rc = gen_password(mathId, mathNum, expireDate, activationKey, hash, password);
    else
        rc = gen_password_v14_0_0(mathId, mathNum, activationKey, hash, password);

    if (rc != 0) {
        printf("Error generating password\n");
        return 1;
    }

    printf("\nHash:       %u\n", hash);
    printf("Act Key:    %s\n", activationKey);
    printf("Password:   %s\n", password);
    return 0;
}
