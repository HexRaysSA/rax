/* Keyed AArch64 PACIA/AUTIA and PACGA with explicit host configuration. */
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include "rax.h"

#define CHECK(call) do { \
    rax_status result = (call); \
    if (result != RAX_OK) { \
        fprintf(stderr, "%s: %s\n", #call, rax_strerror(result)); \
        rax_engine_close(engine); return 1; \
    } \
} while (0)

int main(void) {
    rax_engine *engine = NULL;
    CHECK(rax_engine_open(RAX_ARCH_ARM64, RAX_MODE_64, &engine));
    rax_arm64_pauth_config config = {
        .size = sizeof(config),
        .features = RAX_ARM64_PAUTH_PACA | RAX_ARM64_PAUTH_PACG,
        .algorithm = RAX_ARM64_PAUTH_ALGORITHM_DEFAULT,
        .profile = RAX_ARM64_PAUTH_PROFILE_DEFAULT,
        .reserved = {0, 0, 0, 0}
    };
    CHECK(rax_arm64_pauth_configure(engine, &config));
    CHECK(rax_arm64_pauth_get_config(engine, &config));
    if (config.algorithm != RAX_ARM64_PAUTH_QARMA5 || config.profile != RAX_ARM64_PAUTH_FPACCOMBINE) {
        rax_engine_close(engine); return 1;
    }
    CHECK(rax_reg_write_u64(engine, RAX_ARM64_REG_APIAKEYLO_EL1, UINT64_MAX));
    CHECK(rax_reg_write_u64(engine, RAX_ARM64_REG_APIAKEYHI_EL1, UINT64_C(0x0123456789abcdef)));
    CHECK(rax_reg_write_u64(engine, RAX_ARM64_REG_APGAKEYLO_EL1, UINT64_MAX));
    CHECK(rax_reg_write_u64(engine, RAX_ARM64_REG_APGAKEYHI_EL1, UINT64_C(0x0123456789abcdef)));
    CHECK(rax_reg_write_u64(engine, RAX_ARM64_REG_SCTLR_EL1, UINT64_C(1) << 31));
    CHECK(rax_reg_write_u64(engine, RAX_ARM64_REG_TCR_EL1, 16 | (16 << 16)));
    CHECK(rax_reg_write_u64(engine, RAX_ARM64_REG_HCR_EL2, (UINT64_C(1) << 40) | (UINT64_C(1) << 41)));
    CHECK(rax_reg_write_u64(engine, RAX_ARM64_REG_SCR_EL3, 1 | (1 << 16) | (1 << 17)));
    CHECK(rax_reg_write_u64(engine, RAX_ARM64_X(1), 1));
    const unsigned char code[] = {
        0x20, 0x00, 0xc1, 0xda, /* PACIA X0,X1 */
        0x20, 0x10, 0xc1, 0xda, /* AUTIA X0,X1 */
        0x02, 0x30, 0xc1, 0x9a  /* PACGA X2,X0,X1 */
    };
    CHECK(rax_mem_write(engine, 0x1000, code, sizeof(code)));
    CHECK(rax_emu_start(engine, 0x1000, RAX_NO_ADDR, 0, 1));
    uint64_t value = 0;
    CHECK(rax_reg_read_u64(engine, RAX_ARM64_X(0), &value));
    if (value != UINT64_C(0xf916000000000000)) { rax_engine_close(engine); return 1; }
    CHECK(rax_emu_start(engine, 0x1004, RAX_NO_ADDR, 0, 2));
    CHECK(rax_reg_read_u64(engine, RAX_ARM64_X(0), &value));
    if (value != 0) { rax_engine_close(engine); return 1; }
    CHECK(rax_reg_read_u64(engine, RAX_ARM64_X(2), &value));
    if (value != UINT64_C(0xf996e76100000000)) { rax_engine_close(engine); return 1; }
    printf("PAuth: 3 instructions; QARMA5 known values passed\n");
    rax_engine_close(engine);
    return 0;
}
