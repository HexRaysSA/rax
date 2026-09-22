// Sparse cross-page fetch, with typed diagnostics and exact retirement counts.
#include "rax.hpp"
#include <cstdio>
#include <vector>

int main() {
    try {
        rax_engine_config cfg{};
        cfg.size = sizeof(cfg);
        cfg.arch = RAX_ARCH_X86;
        cfg.mode = RAX_MODE_32;
        cfg.backend = RAX_BACKEND_EMULATOR;
        cfg.mem_base = 0x1000;
        cfg.mem_size = 0x1000;
        cfg.mem_perms = RAX_PROT_ALL;
        rax::Engine engine(cfg);
        engine.memWrite(0x1ffd, std::vector<uint8_t>{0xe9, 0, 0});
        if (engine.startStatus(0x1ffd, 0x2002, 1000000, 1) == rax::Status::Ok)
            return 1;
        const auto fault = engine.lastFault();
        if (fault.kind != RAX_FAULT_UNMAPPED || fault.access != RAX_FAULT_ACCESS_FETCH ||
            fault.flags != RAX_FAULT_ADDRESS_VALID || fault.address != 0x2000 ||
            fault.pc != 0x1ffd || fault.retired_instructions != 0 || engine.icount() != 0)
            return 2;
        engine.memMap(0x2000, 0x1000, RAX_PROT_ALL);
        engine.memWrite(0x2000, std::vector<uint8_t>{0, 0});
        if (engine.lastFault().address != fault.address) return 3;
        engine.start(0x1ffd, 0x2002, 1000000, 1);
        if (engine.icount() != 1 || engine.lastFault().kind != RAX_FAULT_NONE ||
            engine.lastFault().retired_instructions != 1)
            return 4;
        std::puts("typed fault recovery OK");
        return 0;
    } catch (const rax::Error& error) {
        std::fprintf(stderr, "%s\n", error.what());
        return 5;
    }
}
