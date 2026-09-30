// AArch32 user execution, TLS, syscall service, and a cross-engine checkpoint.
#include "rax.hpp"
#include <cstdio>
#include <vector>

int main() {
    try {
        rax_engine_config cfg{};
        cfg.size = sizeof(cfg);
        cfg.arch = RAX_ARCH_ARM;
        cfg.mode = RAX_MODE_USER | RAX_MODE_ARM;
        cfg.mem_base = 0x10000;
        cfg.mem_size = 0x1000;
        cfg.mem_perms = RAX_PROT_READ | RAX_PROT_EXEC;
        rax::Engine engine(cfg);
        std::vector<uint8_t> bytes;
        // mrc p15,0,r0,c13,c0,3 (TPIDRURO); svc #0x1234; bkpt #0x1234.
        for (uint32_t word : {0xee1d0f70u, 0xef001234u, 0xe1212374u})
            for (unsigned shift = 0; shift < 32; shift += 8)
                bytes.push_back(static_cast<uint8_t>(word >> shift));
        engine.memWrite(0x10000, bytes);
        engine.setReg(RAX_ARM_REG_TPIDRURO, uint32_t(0x70001000));
        const auto before = engine.contextSave();
        engine.start(0x10000);
        const auto call = engine.lastSyscall();
        if (engine.lastExit().reason != RAX_STOP_SYSCALL ||
            engine.regU64(RAX_ARM_R(0)) != 0x70001000 || call.pc != 0x10004 ||
            call.resume_pc != 0x10008 || call.size != 4 || call.immediate != 0x1234)
            return 1;

        rax::Engine restored(cfg);
        restored.contextRestore(before);
        unsigned calls = 0;
        restored.hookSyscall([&](rax::Engine &guest, uint64_t, uint32_t, uint32_t) {
            ++calls;
            guest.setReg(RAX_ARM_R(0), uint32_t(42));
        });
        restored.start(0x10000);
        const auto trap = restored.lastException();
        if (calls != 1 || restored.regU64(RAX_ARM_R(0)) != 42 ||
            restored.regU64(RAX_ARM_REG_TPIDRURO) != 0x70001000 ||
            restored.lastExit().reason != RAX_STOP_EXCEPTION || trap.vector != 0x38 ||
            trap.pc != 0x10008 || trap.syndrome != 0x1234)
            return 2;
        std::puts("AArch32 user TLS/syscall/checkpoint OK");
        return 0;
    } catch (const rax::Error &error) {
        std::fprintf(stderr, "%s\n", error.what());
        return 3;
    }
}
