#define _GNU_SOURCE

#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define WIRE_MAGIC 0x58455645u /* 'E','V','E','X' */
#define ZMM_REGS 32
#define K_REGS 8
#define SCRATCH_BYTES 256

#ifndef EVEX_DIFF_CASES_INC
#error "EVEX_DIFF_CASES_INC must name the generated case switch include"
#endif

struct in_case {
    uint32_t id;
    uint32_t reserved;
    uint64_t zmm[ZMM_REGS][8];
    uint64_t k[K_REGS];
    uint8_t scratch[SCRATCH_BYTES];
};

struct out_case {
    uint32_t id;
    uint32_t valid;
    uint64_t zmm[ZMM_REGS][8];
    uint64_t k[K_REGS];
    uint8_t scratch[SCRATCH_BYTES];
};

static sigjmp_buf sigill_jmp;
static volatile sig_atomic_t sigill_active;

static void sigill_handler(int signo) {
    (void)signo;
    if (sigill_active) {
        siglongjmp(sigill_jmp, 1);
    }
    _Exit(111);
}

#define LOAD_ZMM(n, off) "vmovups " #off "(%[zin]), %%zmm" #n "\n\t"
#define STORE_ZMM(n, off) "vmovups %%zmm" #n ", " #off "(%[zout])\n\t"
#define LOAD_K(n, off) "kmovq " #off "(%[kin]), %%k" #n "\n\t"
#define STORE_K(n, off) "kmovq %%k" #n ", " #off "(%[kout])\n\t"

#define LOAD_ALL_ZMM                                                                  \
    LOAD_ZMM(0, 0)                                                                     \
    LOAD_ZMM(1, 64)                                                                    \
    LOAD_ZMM(2, 128)                                                                   \
    LOAD_ZMM(3, 192)                                                                   \
    LOAD_ZMM(4, 256)                                                                   \
    LOAD_ZMM(5, 320)                                                                   \
    LOAD_ZMM(6, 384)                                                                   \
    LOAD_ZMM(7, 448)                                                                   \
    LOAD_ZMM(8, 512)                                                                   \
    LOAD_ZMM(9, 576)                                                                   \
    LOAD_ZMM(10, 640)                                                                  \
    LOAD_ZMM(11, 704)                                                                  \
    LOAD_ZMM(12, 768)                                                                  \
    LOAD_ZMM(13, 832)                                                                  \
    LOAD_ZMM(14, 896)                                                                  \
    LOAD_ZMM(15, 960)                                                                  \
    LOAD_ZMM(16, 1024)                                                                 \
    LOAD_ZMM(17, 1088)                                                                 \
    LOAD_ZMM(18, 1152)                                                                 \
    LOAD_ZMM(19, 1216)                                                                 \
    LOAD_ZMM(20, 1280)                                                                 \
    LOAD_ZMM(21, 1344)                                                                 \
    LOAD_ZMM(22, 1408)                                                                 \
    LOAD_ZMM(23, 1472)                                                                 \
    LOAD_ZMM(24, 1536)                                                                 \
    LOAD_ZMM(25, 1600)                                                                 \
    LOAD_ZMM(26, 1664)                                                                 \
    LOAD_ZMM(27, 1728)                                                                 \
    LOAD_ZMM(28, 1792)                                                                 \
    LOAD_ZMM(29, 1856)                                                                 \
    LOAD_ZMM(30, 1920)                                                                 \
    LOAD_ZMM(31, 1984)

#define STORE_ALL_ZMM                                                                 \
    STORE_ZMM(0, 0)                                                                    \
    STORE_ZMM(1, 64)                                                                   \
    STORE_ZMM(2, 128)                                                                  \
    STORE_ZMM(3, 192)                                                                  \
    STORE_ZMM(4, 256)                                                                  \
    STORE_ZMM(5, 320)                                                                  \
    STORE_ZMM(6, 384)                                                                  \
    STORE_ZMM(7, 448)                                                                  \
    STORE_ZMM(8, 512)                                                                  \
    STORE_ZMM(9, 576)                                                                  \
    STORE_ZMM(10, 640)                                                                 \
    STORE_ZMM(11, 704)                                                                 \
    STORE_ZMM(12, 768)                                                                 \
    STORE_ZMM(13, 832)                                                                 \
    STORE_ZMM(14, 896)                                                                 \
    STORE_ZMM(15, 960)                                                                 \
    STORE_ZMM(16, 1024)                                                                \
    STORE_ZMM(17, 1088)                                                                \
    STORE_ZMM(18, 1152)                                                                \
    STORE_ZMM(19, 1216)                                                                \
    STORE_ZMM(20, 1280)                                                                \
    STORE_ZMM(21, 1344)                                                                \
    STORE_ZMM(22, 1408)                                                                \
    STORE_ZMM(23, 1472)                                                                \
    STORE_ZMM(24, 1536)                                                                \
    STORE_ZMM(25, 1600)                                                                \
    STORE_ZMM(26, 1664)                                                                \
    STORE_ZMM(27, 1728)                                                                \
    STORE_ZMM(28, 1792)                                                                \
    STORE_ZMM(29, 1856)                                                                \
    STORE_ZMM(30, 1920)                                                                \
    STORE_ZMM(31, 1984)

#define LOAD_ALL_K                                                                    \
    LOAD_K(0, 0)                                                                       \
    LOAD_K(1, 8)                                                                       \
    LOAD_K(2, 16)                                                                      \
    LOAD_K(3, 24)                                                                      \
    LOAD_K(4, 32)                                                                      \
    LOAD_K(5, 40)                                                                      \
    LOAD_K(6, 48)                                                                      \
    LOAD_K(7, 56)

#define STORE_ALL_K                                                                   \
    STORE_K(0, 0)                                                                      \
    STORE_K(1, 8)                                                                      \
    STORE_K(2, 16)                                                                     \
    STORE_K(3, 24)                                                                     \
    STORE_K(4, 32)                                                                     \
    STORE_K(5, 40)                                                                     \
    STORE_K(6, 48)                                                                     \
    STORE_K(7, 56)

#define ZMM_CLOBBERS                                                                  \
    "zmm0", "zmm1", "zmm2", "zmm3", "zmm4", "zmm5", "zmm6", "zmm7",              \
        "zmm8", "zmm9", "zmm10", "zmm11", "zmm12", "zmm13", "zmm14", "zmm15",  \
        "zmm16", "zmm17", "zmm18", "zmm19", "zmm20", "zmm21", "zmm22",          \
        "zmm23", "zmm24", "zmm25", "zmm26", "zmm27", "zmm28", "zmm29",          \
        "zmm30", "zmm31"

#define K_CLOBBERS "k0", "k1", "k2", "k3", "k4", "k5", "k6", "k7"

#define RUN_OP(OP)                                                                    \
    __asm__ volatile(                                                                 \
        LOAD_ALL_ZMM                                                                  \
        LOAD_ALL_K                                                                    \
        "movq %[scratch], %%rax\n\t"                                                  \
        OP "\n\t"                                                                     \
        STORE_ALL_ZMM                                                                 \
        STORE_ALL_K                                                                   \
        :                                                                             \
        : [zin] "r"(in->zmm), [kin] "r"(in->k), [scratch] "r"(scratch),              \
          [zout] "r"(out->zmm), [kout] "r"(out->k)                                   \
        : "rax", ZMM_CLOBBERS, K_CLOBBERS, "memory")

static void execute_case(const struct in_case *in, struct out_case *out) {
    _Alignas(64) uint8_t scratch[SCRATCH_BYTES];

    out->id = in->id;
    out->valid = 1;
    memset(out->zmm, 0, sizeof(out->zmm));
    memset(out->k, 0, sizeof(out->k));
    memcpy(scratch, in->scratch, sizeof(scratch));

    if (sigsetjmp(sigill_jmp, 1) == 0) {
        sigill_active = 1;
        switch (in->id) {
#include EVEX_DIFF_CASES_INC
        default:
            out->valid = 0;
            break;
        }
        sigill_active = 0;
    } else {
        sigill_active = 0;
        out->valid = 0;
        memcpy(out->zmm, in->zmm, sizeof(out->zmm));
        memcpy(out->k, in->k, sizeof(out->k));
    }

    memcpy(out->scratch, scratch, sizeof(out->scratch));
}

int main(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigill_handler;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGILL, &sa, NULL) != 0) {
        return 2;
    }

    uint32_t header[2];
    if (fread(header, sizeof(header), 1, stdin) != 1) {
        return 3;
    }
    if (header[0] != WIRE_MAGIC) {
        return 4;
    }

    if (fwrite(header, sizeof(header), 1, stdout) != 1) {
        return 5;
    }

    for (uint32_t i = 0; i < header[1]; i++) {
        struct in_case in;
        struct out_case out;
        if (fread(&in, sizeof(in), 1, stdin) != 1) {
            return 6;
        }
        execute_case(&in, &out);
        if (fwrite(&out, sizeof(out), 1, stdout) != 1) {
            return 7;
        }
    }

    return 0;
}
