// A self-contained PE32+ image: MOV EAX,42; RET. PE/COFF fields use their
// specified little-endian on-disk layout, independent of the host platform.
// Layout reference: docs/specifications/windows/microsoft-docs/pe-format.md.
#include "rax.hpp"
#include <cstdio>
#include <utility>

static std::vector<uint8_t> image() {
    std::vector<uint8_t> bytes(0x400);
    const auto put = [&](size_t at, uint64_t value, size_t width) {
        for (size_t i = 0; i < width; ++i)
            bytes[at + i] = uint8_t(value >> (8 * i));
    };
    put(0, 0x5A4D, 2);
    put(0x3C, 0x80, 4);
    put(0x80, 0x00004550, 4); // PE signature
    put(0x84, 0x8664, 2);
    put(0x86, 1, 2); // AMD64, one section
    put(0x94, 0xF0, 2);
    put(0x96, 0x22, 2); // optional-header size, EXE+large-address
    const size_t o = 0x98;
    put(o, 0x20B, 2);
    put(o + 4, 0x200, 4);
    put(o + 16, 0x1000, 4);
    put(o + 20, 0x1000, 4);
    put(o + 24, 0x140000000ULL, 8);
    put(o + 32, 0x1000, 4);
    put(o + 36, 0x200, 4);
    put(o + 40, 6, 2);
    put(o + 48, 6, 2);
    put(o + 56, 0x2000, 4);
    put(o + 60, 0x200, 4);
    put(o + 68, 3, 2);
    put(o + 70, 0x100, 2); // console, NX-compatible
    put(o + 72, 0x100000, 8);
    put(o + 80, 0x1000, 8);
    put(o + 88, 0x100000, 8);
    put(o + 96, 0x1000, 8);
    put(o + 108, 16, 4);
    const size_t s = o + 0xF0;
    std::memcpy(bytes.data() + s, ".text", 5);
    put(s + 8, 6, 4);
    put(s + 12, 0x1000, 4);
    put(s + 16, 0x200, 4);
    put(s + 20, 0x200, 4);
    put(s + 36, 0x60000020, 4); // code, read, execute
    const uint8_t code[] = {0xB8, 42, 0, 0, 0, 0xC3};
    std::memcpy(bytes.data() + 0x200, code, sizeof(code));
    return bytes;
}

// ELF64 ET_EXEC with one RX PT_LOAD, executing Linux exit(37).
static std::vector<uint8_t> elf_image() {
    std::vector<uint8_t> bytes(8192);
    const auto put = [&](size_t at, uint64_t value, size_t width) {
        for (size_t i = 0; i < width; ++i) bytes[at+i] = uint8_t(value >> (8*i));
    };
    const uint8_t ident[] = {0x7f, 'E', 'L', 'F', 2, 1, 1};
    std::memcpy(bytes.data(), ident, sizeof(ident));
    put(16, 2, 2); put(18, 62, 2); put(20, 1, 4);
    put(24, 0x401000, 8); put(32, 64, 8);
    put(52, 64, 2); put(54, 56, 2); put(56, 1, 2);
    put(64, 1, 4); put(68, 5, 4);
    put(80, 0x400000, 8); put(88, 0x400000, 8);
    put(96, 8192, 8); put(104, 8192, 8); put(112, 4096, 8);
    const uint8_t code[] = {0xb8, 60, 0, 0, 0, 0xbf, 37, 0, 0, 0, 0x0f, 0x05};
    std::memcpy(bytes.data()+4096, code, sizeof(code));
    return bytes;
}

int main() {
    try {
        rax::Process first(image(), R"({"memory_bytes":67108864,"slice_instructions":1})");
        rax::Process process(std::move(first));
        if (process.infoJson().find("\"personality\":\"windows\"") == std::string::npos)
            return 1;
        const auto header = process.readMemory(0x140000000ULL, 2);
        if (header != std::vector<uint8_t>{'M', 'Z'})
            return 2;
        process.setCancelled();
        if (process.run(1).reason != RAX_PROCESS_CANCELLED)
            return 3;
        process.setCancelled(false);
        auto result = process.run(10000, 1000000);
        if (result.reason != RAX_PROCESS_EXITED || result.exit_code != 42)
            return 4;
        result = process.run(1);
        if (result.reason != RAX_PROCESS_EXITED || result.turns_started != 0)
            return 5;
        if (!process.readOutput(RAX_PROCESS_STDOUT, 16).empty())
            return 6;
        rax::Process elf(elf_image(), R"({"personality":"linux"})");
        if (elf.infoJson().find("\"context_format\":\"linux_prstatus\"") == std::string::npos)
            return 8;
        result = elf.run(16);
        if (result.reason != RAX_PROCESS_EXITED || result.exit_code != 37)
            return 9;
        std::puts("ELF process: exit 37; closed Linux profile OK");
        std::puts("PE process: exit 42; captured console; resumable cancellation; RAII OK");
        return 0;
    } catch (const std::exception &error) {
        std::fprintf(stderr, "%s\n", error.what());
        return 7;
    }
}
