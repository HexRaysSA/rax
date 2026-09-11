#include "rax.hpp"
#include <cstring>
#include <cstdio>
int main() {
    try {
        const unsigned char code[] = {0xc2, 0x10, 0};
        for (auto mode : {RAX_MODE_16, RAX_MODE_32, RAX_MODE_64}) {
            const auto info = rax::instructionInfo(rax::Arch::X86, mode, 0x1000, code, sizeof(code));
            const int width = mode == RAX_MODE_16 ? 2 : mode == RAX_MODE_32 ? 4 : 8;
            if (!info.decoded.valid || info.decoded.size != 3 || info.decoded.flow != RAX_FLOW_RETURN ||
                std::strcmp(info.mnemonic, "ret") || info.stack_pointer_increment != width + 16 ||
                !(info.flags & RAX_INSTRUCTION_BASIC_COMPLETE)) return 1;
        }
        std::puts("native x86 instruction metadata OK");
        return 0;
    } catch (const rax::Error& error) {
        std::fprintf(stderr, "%s\n", error.what()); return 2;
    }
}
