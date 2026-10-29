// Optional AArch64 FP/SIMD features selected through the public C++ and C API.
#include "rax.hpp"
#include <array>
#include <cstdio>
#include <vector>

namespace {

std::vector<uint8_t> wordBytes(uint32_t word) {
    std::vector<uint8_t> bytes;
    for (unsigned shift = 0; shift < 32; shift += 8) {
        bytes.push_back(static_cast<uint8_t>(word >> shift));
    }
    return bytes;
}

rax_engine_config engineConfig(bool user) {
    rax_engine_config config{};
    config.size = sizeof(config);
    config.arch = RAX_ARCH_ARM64;
    config.mode = RAX_MODE_64 | (user ? RAX_MODE_USER : 0u);
    config.mem_size = 0x4000;
    config.mem_perms = RAX_PROT_ALL;
    return config;
}

} // namespace

int main() {
    try {
        struct Case { uint32_t features; uint32_t word; };
        const std::array<Case, 8> cases{{
            {RAX_ARM64_FEATURE_FP16, 0x1ee22820},
            {RAX_ARM64_FEATURE_FP16 | RAX_ARM64_FEATURE_FHM, 0x0e22ec20},
            {RAX_ARM64_FEATURE_JSCVT, 0x1e7e0020},
            {RAX_ARM64_FEATURE_FCMA, 0x6e82e420},
            {RAX_ARM64_FEATURE_FRINTTS, 0x1e284020},
            {RAX_ARM64_FEATURE_BF16, 0x1e634020},
            {RAX_ARM64_FEATURE_I8MM, 0x4e82a420},
            {RAX_ARM64_FEATURE_DOTPROD, 0x4e829420}
        }};
        for (bool user : {false, true}) {
            for (const auto& test : cases) {
                rax::Engine engine(engineConfig(user));
                if (engine.fpConfig().features != 0) return 1;
                engine.memWrite(0x100, wordBytes(test.word));
                engine.setReg(RAX_ARM64_REG_PC, uint64_t(0x100));
                uint64_t retired = UINT64_MAX;
                const auto status = rax_emu_step(engine.raw(), 1, &retired);
                if ((user && status != RAX_OK) || (!user && status == RAX_OK) || retired != 0 ||
                    engine.regU64(RAX_ARM64_REG_PC) != 0x100 || rax_emu_icount(engine.raw()) != 0)
                    return 2;
                if (user) {
                    const auto exit = engine.lastExit();
                    if (exit.reason != RAX_STOP_EXCEPTION || exit.intno != 0) return 3;
                }
                rax_arm64_fp_config selection{};
                selection.size = sizeof(selection);
                selection.features = test.features;
                engine.configureFp(selection);
                if (engine.fpConfig().features != test.features || engine.step() != 1 ||
                    engine.regU64(RAX_ARM64_REG_PC) != 0x104 || rax_emu_icount(engine.raw()) != 1)
                    return 4;

                selection.features = RAX_ARM64_FP_FEATURES_SUPPORTED;
                engine.configureFp(selection);
                size_t size = 0;
                if (rax_context_save(engine.raw(), nullptr, 0, &size) != RAX_OK) return 5;
                std::vector<uint8_t> context(size);
                if (rax_context_save(engine.raw(), context.data(), context.size(), &size) != RAX_OK)
                    return 6;
                selection.features = 0;
                engine.configureFp(selection);
                if (rax_context_restore(engine.raw(), context.data(), size) != RAX_OK ||
                    engine.fpConfig().features != RAX_ARM64_FP_FEATURES_SUPPORTED)
                    return 7;
                if (rax_mem_map(engine.raw(), 0x8000, 0x1000, RAX_PROT_ALL) != RAX_OK ||
                    engine.fpConfig().features != RAX_ARM64_FP_FEATURES_SUPPORTED)
                    return 8;
                engine.reset();
                if (engine.fpConfig().features != RAX_ARM64_FP_FEATURES_SUPPORTED) return 9;
            }
        }
        std::puts("AArch64 FP profile: 16 public feature retries, reset/context/map checks passed");
        return 0;
    } catch (const rax::Error& error) {
        std::fprintf(stderr, "%s\n", error.what());
        return 10;
    }
}
