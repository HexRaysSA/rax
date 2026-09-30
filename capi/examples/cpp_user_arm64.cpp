// AArch64 user mode from C++: an EL0 program reads its thread pointer, makes
// a system call serviced by a lambda, and stops at a BRK breakpoint.
#include "rax.hpp"
#include <cstdio>
#include <vector>

namespace {

// Serialize instruction words little-endian independently of the host.
std::vector<uint8_t> words(std::initializer_list<uint32_t> insns) {
    std::vector<uint8_t> bytes;
    for (uint32_t insn : insns)
        for (int shift = 0; shift < 32; shift += 8)
            bytes.push_back(static_cast<uint8_t>(insn >> shift));
    return bytes;
}

} // namespace

int main() {
    try {
        rax_engine_config cfg{};
        cfg.size = sizeof(cfg);
        cfg.arch = RAX_ARCH_ARM64;
        cfg.mode = RAX_MODE_USER;
        cfg.mem_base = 0x10000;
        cfg.mem_size = 0x10000;
        cfg.mem_perms = RAX_PROT_READ | RAX_PROT_EXEC;
        rax::Engine engine(cfg);

        // mrs x19, tpidr_el0 ; movz x8, #172 (getpid) ; svc #0 ; brk #7
        const auto code = words({0xD53BD053, 0xD2801588, 0xD4000001, 0xD42000E0});
        engine.memWrite(0x10000, code);
        engine.setReg(RAX_ARM64_REG_TPIDR_EL0, uint64_t(0x7000'0000'1000));

        int calls = 0;
        engine.hookSyscall([&](rax::Engine& e, uint64_t pc, uint32_t insn, uint32_t imm) {
            ++calls;
            const uint64_t nr = e.regU64(RAX_ARM64_X(8));
            std::printf("svc #%u at 0x%llx: syscall %llu\n", imm, (unsigned long long)pc,
                        (unsigned long long)nr);
            // getpid() returns 4242; anything else is -ENOSYS.
            e.setReg(RAX_ARM64_X(0), nr == 172 ? uint64_t(4242) : uint64_t(-38));
            if (insn != RAX_SYSCALL_INSN_SVC || pc != 0x10008) e.stop();
        });

        engine.start(0x10000);
        const auto exit = engine.lastExit();
        const auto brk = engine.lastException();
        const auto syscall = engine.lastSyscall();
        if (syscall.flags != RAX_SYSCALL_VALID || syscall.pc != 0x10008 ||
            syscall.resume_pc != 0x1000C || syscall.size != 4 ||
            syscall.instruction != RAX_SYSCALL_INSN_SVC || syscall.immediate != 0)
            return 4;
        std::printf("stopped: reason %d vector 0x%x syndrome %llu at 0x%llx\n", exit.reason,
                    brk.vector, (unsigned long long)brk.syndrome, (unsigned long long)brk.pc);
        if (calls != 1 || engine.regU64(RAX_ARM64_X(0)) != 4242 ||
            engine.regU64(RAX_ARM64_X(19)) != 0x7000'0000'1000 ||
            exit.reason != RAX_STOP_EXCEPTION || brk.vector != 0x3C || brk.syndrome != 7 ||
            (brk.flags & RAX_EXCEPTION_SOFTWARE) == 0 || brk.pc != 0x1000C ||
            engine.regU64(RAX_ARM64_REG_PC) != 0x1000C)
            return 1;

        // The stateless decoder agrees on the SVC instruction.
        const std::vector<uint8_t> svc(code.begin() + 8, code.begin() + 12);
        const auto decoded = rax::decode(rax::Arch::Arm64, 0, 0x10008, svc);
        const auto analysis = rax::analyze(rax::Arch::Arm64, 0, 0x10008, svc);
        std::printf("decode: size %u flow %d; analysis flags 0x%x, %zu effects\n",
                    decoded.size, decoded.flow, analysis.summary.flags, analysis.effects.size());
        if (!decoded.valid || decoded.size != 4 ||
            (analysis.summary.flags & RAX_ANALYSIS_VALID) == 0 ||
            analysis.effects.size() != analysis.summary.effect_count)
            return 2;
        std::puts("AArch64 user mode OK");
        return 0;
    } catch (const rax::Error& error) {
        std::fprintf(stderr, "%s\n", error.what());
        return 3;
    }
}
