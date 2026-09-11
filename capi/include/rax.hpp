// rax.hpp — Idiomatic C++ wrapper for the RAX emulation engine.
//
// Header-only, C++17. Wraps the stable C ABI in `rax.h` with RAII, type-safe
// register access, std::function-based hooks (lambdas welcome), and exceptions
// for error handling. Include this instead of (or alongside) rax.h.
//
//   #include <rax.hpp>
//   rax::Engine e(rax::Arch::X86, RAX_MODE_64);
//   e.memWrite(0x1000, code, sizeof(code));
//   e.setReg(RAX_X86_REG_RIP, uint64_t(0x1000));
//   e.start(0x1000);
//   uint64_t result = e.regU64(RAX_X86_REG_RAX);
//
// Exceptions: fallible operations throw rax::Error (carrying a Status and a
// message). The `*Status` variants return a Status and never throw.

#ifndef RAX_HPP
#define RAX_HPP

#include "rax.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <functional>
#include <memory>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <vector>

namespace rax {

// --- Enums ----------------------------------------------------------------

enum class Arch : int {
    X86     = RAX_ARCH_X86,
    Arm64   = RAX_ARCH_ARM64,
    Arm     = RAX_ARCH_ARM,
    Riscv64 = RAX_ARCH_RISCV64,
    Hexagon = RAX_ARCH_HEXAGON,
    CortexM = RAX_ARCH_CORTEXM,
};

enum class Status : int {
    Ok          = RAX_OK,
    NoMem       = RAX_ERR_NOMEM,
    Arg         = RAX_ERR_ARG,
    Handle      = RAX_ERR_HANDLE,
    ArchErr     = RAX_ERR_ARCH,
    Backend     = RAX_ERR_BACKEND,
    Mode        = RAX_ERR_MODE,
    Map         = RAX_ERR_MAP,
    Perm        = RAX_ERR_PERM,
    Bounds      = RAX_ERR_BOUNDS,
    Reg         = RAX_ERR_REG,
    State       = RAX_ERR_STATE,
    Fault       = RAX_ERR_FAULT,
    Io          = RAX_ERR_IO,
    Format      = RAX_ERR_FORMAT,
    Hook        = RAX_ERR_HOOK,
    Unsupported = RAX_ERR_UNSUPPORTED,
    Internal    = RAX_ERR_INTERNAL,
};

using Exit = rax_exit;
using FaultInfo = rax_fault_info;
using MemRegion = rax_mem_region;

inline const char* strerror(Status s) { return rax_strerror(static_cast<int>(s)); }

// --- Error ----------------------------------------------------------------

class Error : public std::runtime_error {
public:
    explicit Error(Status s, std::string ctx = {})
        : std::runtime_error(build(s, ctx)), status_(s) {}
    Status status() const noexcept { return status_; }

private:
    Status status_;
    static std::string build(Status s, const std::string& ctx) {
        std::string m = rax_strerror(static_cast<int>(s));
        if (!ctx.empty()) m = ctx + ": " + m;
        return m;
    }
};

inline void check(rax_status s, const char* ctx = nullptr) {
    if (s != RAX_OK) throw Error(static_cast<Status>(s), ctx ? ctx : "");
}

// Stateless metadata uses the same guest mode as the native RAX decoder.
using InstructionInfo = rax_instruction_info_t;
inline InstructionInfo instructionInfo(Arch arch, uint32_t mode, uint64_t pc,
                                       const void* bytes, size_t len) {
    InstructionInfo info{};
    info.struct_size = sizeof(info);
    info.abi_version = RAX_INSTRUCTION_INFO_VERSION;
    check(rax_instruction_info(static_cast<int>(arch), mode, pc, bytes, len, &info),
          "rax_instruction_info");
    return info;
}

// --- Hook thunks ----------------------------------------------------------
//
// std::function hooks are owned by the Engine. Each is heap-allocated so its
// address is stable; it is passed as the C `user` pointer. The owning Engine
// pointer is fixed up on move.

class Engine; // fwd

namespace detail {

// The C ABI transfers raw register buffers little-endian. Arithmetic/enum
// template arguments represent native scalar values; other trivially copyable
// arguments (for example vector byte arrays) retain their byte representation.
template <class T> void convertScalarByteOrder(unsigned char* bytes) {
    if constexpr (std::is_arithmetic_v<T> || std::is_enum_v<T>) {
        const uint16_t one = 1;
        if (*reinterpret_cast<const unsigned char*>(&one) == 0)
            std::reverse(bytes, bytes + sizeof(T));
    }
}

struct Hook {
    Engine* owner = nullptr;
    uint32_t id = 0;
    std::function<void(Engine&, uint64_t, uint32_t)> code;       // code/block
    std::function<void(Engine&, uint32_t)> intr;
    std::function<uint64_t(Engine&, uint32_t, uint32_t)> ioIn;
    std::function<void(Engine&, uint32_t, uint32_t, uint64_t)> ioOut;
    std::function<uint64_t(Engine&, uint64_t, uint32_t)> mmioRead;
    std::function<void(Engine&, uint64_t, uint32_t, uint64_t)> mmioWrite;
    std::function<bool(Engine&, uint64_t)> invalid;
    std::function<void(Engine&, int, uint64_t, uint32_t, uint64_t)> mem;
};

} // namespace detail

// --- Engine ---------------------------------------------------------------

class Engine {
public:
    using CodeFn = std::function<void(Engine&, uint64_t /*addr*/, uint32_t /*size*/)>;
    using IntrFn = std::function<void(Engine&, uint32_t /*intno*/)>;
    using IoInFn = std::function<uint64_t(Engine&, uint32_t /*port*/, uint32_t /*size*/)>;
    using IoOutFn = std::function<void(Engine&, uint32_t /*port*/, uint32_t /*size*/, uint64_t /*value*/)>;
    using MmioReadFn = std::function<uint64_t(Engine&, uint64_t /*addr*/, uint32_t /*size*/)>;
    using MmioWriteFn = std::function<void(Engine&, uint64_t /*addr*/, uint32_t /*size*/, uint64_t /*value*/)>;
    using InvalidFn = std::function<bool(Engine&, uint64_t /*addr*/)>;
    using MemFn = std::function<void(Engine&, int /*kind*/, uint64_t /*addr*/, uint32_t /*size*/, uint64_t /*value*/)>;

    // -- lifecycle --
    Engine(Arch arch, uint32_t mode) {
        rax_engine* h = nullptr;
        check(rax_engine_open(static_cast<int>(arch), mode, &h), "rax_engine_open");
        h_ = h;
    }
    explicit Engine(const rax_engine_config& cfg) {
        rax_engine* h = nullptr;
        check(rax_engine_open_config(&cfg, &h), "rax_engine_open_config");
        h_ = h;
    }
    ~Engine() {
        if (h_) rax_engine_close(h_);
    }
    Engine(const Engine&) = delete;
    Engine& operator=(const Engine&) = delete;
    Engine(Engine&& o) noexcept { moveFrom(std::move(o)); }
    Engine& operator=(Engine&& o) noexcept {
        if (this != &o) {
            if (h_) rax_engine_close(h_);
            hooks_.clear();
            moveFrom(std::move(o));
        }
        return *this;
    }

    rax_engine* raw() const noexcept { return h_; }

    void reset() { check(rax_engine_reset(h_), "reset"); }
    Arch arch() const noexcept { return static_cast<Arch>(rax_engine_arch(h_)); }
    uint32_t mode() const noexcept { return rax_engine_mode(h_); }
    bool supportsStepping() const noexcept { return rax_engine_supports_stepping(h_) != 0; }

    std::string errmsg() const {
        int n = rax_engine_errmsg(h_, nullptr, 0);
        if (n <= 0) return {};
        std::string s(static_cast<size_t>(n), '\0');
        rax_engine_errmsg(h_, &s[0], s.size() + 1);
        return s;
    }

    // -- memory --
    void memMap(uint64_t addr, uint64_t size, uint32_t perms) {
        check(rax_mem_map(h_, addr, size, perms), "mem_map");
    }
    void memUnmap(uint64_t addr, uint64_t size) {
        check(rax_mem_unmap(h_, addr, size), "mem_unmap");
    }
    void memProtect(uint64_t addr, uint64_t size, uint32_t perms) {
        check(rax_mem_protect(h_, addr, size, perms), "mem_protect");
    }
    void memWrite(uint64_t addr, const void* data, size_t len) {
        check(rax_mem_write(h_, addr, data, len), "mem_write");
    }
    void memWrite(uint64_t addr, const std::vector<uint8_t>& d) { memWrite(addr, d.data(), d.size()); }
    void memRead(uint64_t addr, void* data, size_t len) {
        check(rax_mem_read(h_, addr, data, len), "mem_read");
    }
    std::vector<uint8_t> memRead(uint64_t addr, size_t len) {
        std::vector<uint8_t> v(len);
        if (len) memRead(addr, v.data(), len);
        return v;
    }
    void memWriteVirt(uint64_t vaddr, const void* data, size_t len) {
        check(rax_mem_write_virt(h_, vaddr, data, len), "mem_write_virt");
    }
    void memReadVirt(uint64_t vaddr, void* data, size_t len) {
        check(rax_mem_read_virt(h_, vaddr, data, len), "mem_read_virt");
    }
    uint64_t translate(uint64_t vaddr, int access = RAX_ACCESS_READ) {
        uint64_t pa = 0;
        check(rax_mem_translate(h_, vaddr, access, &pa), "mem_translate");
        return pa;
    }
    std::vector<MemRegion> regions() const {
        size_t n = 0;
        check(rax_mem_regions(h_, nullptr, &n), "mem_regions");
        std::vector<MemRegion> v(n);
        if (n) check(rax_mem_regions(h_, v.data(), &n), "mem_regions");
        v.resize(n);
        return v;
    }

    // -- registers --
    static size_t regSize(Arch arch, int regid) {
        return rax_reg_size(static_cast<int>(arch), regid);
    }
    size_t regSize(int regid) const { return rax_reg_size(rax_engine_arch(h_), regid); }

    // Typed scalar read/write (T must be trivially copyable and match the
    // register's natural width). Arithmetic/enum values use native byte order;
    // aggregate values retain the C API's raw byte representation.
    template <class T> T reg(int regid) {
        static_assert(std::is_trivially_copyable_v<T>, "register type must be trivially copyable");
        T v{};
        size_t out = 0;
        check(rax_reg_read(h_, regid, &v, &out), "reg_read");
        detail::convertScalarByteOrder<T>(reinterpret_cast<unsigned char*>(&v));
        return v;
    }
    template <class T> void setReg(int regid, const T& v) {
        static_assert(std::is_trivially_copyable_v<T>, "register type must be trivially copyable");
        unsigned char bytes[sizeof(T)];
        std::memcpy(bytes, &v, sizeof(T));
        detail::convertScalarByteOrder<T>(bytes);
        check(rax_reg_write(h_, regid, bytes), "reg_write");
    }
    uint64_t regU64(int regid) {
        uint64_t v = 0;
        check(rax_reg_read_u64(h_, regid, &v), "reg_read_u64");
        return v;
    }
    void setReg(int regid, uint64_t v) { check(rax_reg_write_u64(h_, regid, v), "reg_write_u64"); }

    std::vector<uint8_t> regBytes(int regid) {
        size_t sz = regSize(regid);
        std::vector<uint8_t> v(sz);
        size_t out = 0;
        check(rax_reg_read(h_, regid, v.data(), &out), "reg_read");
        v.resize(out);
        return v;
    }
    void setRegBytes(int regid, const std::vector<uint8_t>& v) {
        check(rax_reg_write(h_, regid, v.data()), "reg_write");
    }

    // -- execution --
    Status start(uint64_t begin, uint64_t until = RAX_NO_ADDR, uint64_t timeoutUs = 0,
                 uint64_t count = 0) {
        rax_status s = rax_emu_start(h_, begin, until, timeoutUs, count);
        if (s != RAX_OK) throw Error(static_cast<Status>(s), "emu_start");
        return Status::Ok;
    }
    // Non-throwing variant: returns the status; inspect lastExit() for the reason.
    Status startStatus(uint64_t begin, uint64_t until = RAX_NO_ADDR, uint64_t timeoutUs = 0,
                       uint64_t count = 0) noexcept {
        return static_cast<Status>(rax_emu_start(h_, begin, until, timeoutUs, count));
    }
    uint64_t step(uint64_t count = 1) {
        uint64_t executed = 0;
        check(rax_emu_step(h_, count, &executed), "emu_step");
        return executed;
    }
    void stop() { check(rax_emu_stop(h_), "emu_stop"); }
    Exit lastExit() const {
        Exit e;
        std::memset(&e, 0, sizeof(e));
        rax_emu_last_exit(h_, &e);
        return e;
    }
    FaultInfo lastFault() const {
        FaultInfo f{};
        f.struct_size = sizeof(f);
        f.version = RAX_FAULT_INFO_VERSION;
        check(rax_emu_last_fault(h_, &f), "emu_last_fault");
        return f;
    }
    uint64_t icount() const noexcept { return rax_emu_icount(h_); }

    // -- interrupts --
    Status interrupt(uint32_t vector) noexcept {
        return static_cast<Status>(rax_interrupt(h_, vector));
    }
    void nmi() { check(rax_nmi(h_), "nmi"); }
    bool canInterrupt() const noexcept { return rax_can_interrupt(h_) != 0; }

    // -- hooks --
    uint32_t hookCode(uint64_t begin, uint64_t end, CodeFn fn) {
        auto* hk = newHook();
        hk->code = std::move(fn);
        uint32_t id = 0;
        check(rax_hook_add_code(h_, begin, end, &Engine::codeTramp, hk, &id), "hook_add_code");
        hk->id = id;
        return id;
    }
    uint32_t hookCode(CodeFn fn) { return hookCode(1, 0, std::move(fn)); } // all addresses
    uint32_t hookBlock(uint64_t begin, uint64_t end, CodeFn fn) {
        auto* hk = newHook();
        hk->code = std::move(fn);
        uint32_t id = 0;
        check(rax_hook_add_block(h_, begin, end, &Engine::codeTramp, hk, &id), "hook_add_block");
        hk->id = id;
        return id;
    }
    uint32_t hookIntr(IntrFn fn) {
        auto* hk = newHook();
        hk->intr = std::move(fn);
        uint32_t id = 0;
        check(rax_hook_add_intr(h_, &Engine::intrTramp, hk, &id), "hook_add_intr");
        hk->id = id;
        return id;
    }
    uint32_t hookIoIn(IoInFn fn) {
        auto* hk = newHook();
        hk->ioIn = std::move(fn);
        uint32_t id = 0;
        check(rax_hook_add_io_in(h_, &Engine::ioInTramp, hk, &id), "hook_add_io_in");
        hk->id = id;
        return id;
    }
    uint32_t hookIoOut(IoOutFn fn) {
        auto* hk = newHook();
        hk->ioOut = std::move(fn);
        uint32_t id = 0;
        check(rax_hook_add_io_out(h_, &Engine::ioOutTramp, hk, &id), "hook_add_io_out");
        hk->id = id;
        return id;
    }
    uint32_t hookMmioRead(MmioReadFn fn) {
        auto* hk = newHook();
        hk->mmioRead = std::move(fn);
        uint32_t id = 0;
        check(rax_hook_add_mmio_read(h_, &Engine::mmioReadTramp, hk, &id), "hook_add_mmio_read");
        hk->id = id;
        return id;
    }
    uint32_t hookMmioWrite(MmioWriteFn fn) {
        auto* hk = newHook();
        hk->mmioWrite = std::move(fn);
        uint32_t id = 0;
        check(rax_hook_add_mmio_write(h_, &Engine::mmioWriteTramp, hk, &id), "hook_add_mmio_write");
        hk->id = id;
        return id;
    }
    uint32_t hookInvalid(InvalidFn fn) {
        auto* hk = newHook();
        hk->invalid = std::move(fn);
        uint32_t id = 0;
        check(rax_hook_add_invalid(h_, &Engine::invalidTramp, hk, &id), "hook_add_invalid");
        hk->id = id;
        return id;
    }
    /// Per-access memory hook. `types` is a mask of RAX_HOOK_MEM_READ/WRITE/FETCH;
    /// `[begin, end]` filters by address (begin > end ⇒ all addresses).
    uint32_t hookMem(uint32_t types, uint64_t begin, uint64_t end, MemFn fn) {
        auto* hk = newHook();
        hk->mem = std::move(fn);
        uint32_t id = 0;
        check(rax_hook_add_mem(h_, types, begin, end, &Engine::memTramp, hk, &id), "hook_add_mem");
        hk->id = id;
        return id;
    }
    uint32_t hookMem(uint32_t types, MemFn fn) { return hookMem(types, 1, 0, std::move(fn)); }
    void hookDel(uint32_t id) {
        check(rax_hook_del(h_, id), "hook_del");
        for (auto it = hooks_.begin(); it != hooks_.end(); ++it) {
            if ((*it)->id == id) { hooks_.erase(it); break; }
        }
    }

    // -- context --
    std::vector<uint8_t> contextSave() const {
        size_t need = 0;
        check(rax_context_save(h_, nullptr, 0, &need), "context_save");
        std::vector<uint8_t> v(need);
        if (need) check(rax_context_save(h_, v.data(), v.size(), &need), "context_save");
        v.resize(need);
        return v;
    }
    void contextRestore(const void* data, size_t len) {
        check(rax_context_restore(h_, data, len), "context_restore");
    }
    void contextRestore(const std::vector<uint8_t>& v) { contextRestore(v.data(), v.size()); }

private:
    rax_engine* h_ = nullptr;
    std::vector<std::unique_ptr<detail::Hook>> hooks_;

    detail::Hook* newHook() {
        hooks_.push_back(std::make_unique<detail::Hook>());
        auto* hk = hooks_.back().get();
        hk->owner = this;
        return hk;
    }

    void moveFrom(Engine&& o) noexcept {
        h_ = o.h_;
        hooks_ = std::move(o.hooks_);
        o.h_ = nullptr;
        for (auto& hk : hooks_) hk->owner = this; // fix up stable thunk back-pointers
    }

    static detail::Hook& hk(void* user) { return *static_cast<detail::Hook*>(user); }

    static void codeTramp(rax_engine*, uint64_t a, uint32_t s, void* u) {
        auto& h = hk(u);
        if (h.code) h.code(*h.owner, a, s);
    }
    static void intrTramp(rax_engine*, uint32_t v, void* u) {
        auto& h = hk(u);
        if (h.intr) h.intr(*h.owner, v);
    }
    static uint64_t ioInTramp(rax_engine*, uint32_t p, uint32_t s, void* u) {
        auto& h = hk(u);
        return h.ioIn ? h.ioIn(*h.owner, p, s) : 0;
    }
    static void ioOutTramp(rax_engine*, uint32_t p, uint32_t s, uint64_t val, void* u) {
        auto& h = hk(u);
        if (h.ioOut) h.ioOut(*h.owner, p, s, val);
    }
    static uint64_t mmioReadTramp(rax_engine*, uint64_t a, uint32_t s, void* u) {
        auto& h = hk(u);
        return h.mmioRead ? h.mmioRead(*h.owner, a, s) : 0;
    }
    static void mmioWriteTramp(rax_engine*, uint64_t a, uint32_t s, uint64_t val, void* u) {
        auto& h = hk(u);
        if (h.mmioWrite) h.mmioWrite(*h.owner, a, s, val);
    }
    static int invalidTramp(rax_engine*, uint64_t a, void* u) {
        auto& h = hk(u);
        return (h.invalid && h.invalid(*h.owner, a)) ? 1 : 0;
    }
    static void memTramp(rax_engine*, int kind, uint64_t a, uint32_t s, uint64_t val, void* u) {
        auto& h = hk(u);
        if (h.mem) h.mem(*h.owner, kind, a, s, val);
    }
};

} // namespace rax

#endif // RAX_HPP
