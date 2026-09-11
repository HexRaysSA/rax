/*
 * rax.h — Stable C API/ABI for the RAX emulation engine.
 *
 * RAX is a cross-platform CPU emulator. This header is its embeddable C
 * interface: open an engine for an architecture, map guest memory at arbitrary
 * addresses, load code and data, read/write the full register file, then run,
 * single-step, or step a bounded number of instructions with complete control
 * over stop conditions and a rich set of execution hooks.
 *
 * Link with -lrax (librax.a / librax.so / librax.dylib).
 *
 * ----------------------------------------------------------------------------
 * ABI & threading contract
 * ----------------------------------------------------------------------------
 *  - Every fallible function returns a `rax_status` (RAX_OK == 0).
 *  - Arguments are validated; NULL handles / bad arguments are reported, never
 *    dereferenced. A Rust panic can never cross this boundary (it becomes
 *    RAX_ERR_INTERNAL).
 *  - An `rax_engine` handle is NOT thread-safe: use one handle from one thread
 *    at a time. Distinct handles are independent and may run concurrently.
 *  - The library never takes ownership of caller buffers; data is copied in/out.
 *  - This ABI is stable: enum values are frozen and only ever appended to;
 *    structs carry a leading size or trailing reserved fields for extension.
 *
 * Numeric values here are the single source of truth, mirrored exactly by the
 * Rust implementation.
 */
#ifndef RAX_H
#define RAX_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32) && defined(RAX_DLL)
#  ifdef RAX_BUILDING
#    define RAX_API __declspec(dllexport)
#  else
#    define RAX_API __declspec(dllimport)
#  endif
#else
#  define RAX_API
#endif

/* ===========================================================================
 * Versioning
 * ======================================================================== */
#define RAX_API_MAJOR 1u
#define RAX_API_MINOR 5u
#define RAX_API_PATCH 0u

/* ===========================================================================
 * Status codes
 * ======================================================================== */
typedef enum rax_status {
    RAX_OK              = 0,  /* success */
    RAX_ERR_NOMEM       = 1,  /* host allocation failed */
    RAX_ERR_ARG         = 2,  /* invalid argument (NULL, bad value, ...) */
    RAX_ERR_HANDLE      = 3,  /* NULL or invalid engine handle */
    RAX_ERR_ARCH        = 4,  /* unsupported architecture */
    RAX_ERR_BACKEND     = 5,  /* unavailable/incompatible backend */
    RAX_ERR_MODE        = 6,  /* invalid CPU mode flags */
    RAX_ERR_MAP         = 7,  /* mapping error / unmapped access */
    RAX_ERR_PERM        = 8,  /* permission violation */
    RAX_ERR_BOUNDS      = 9,  /* address/length out of range */
    RAX_ERR_REG         = 10, /* invalid register id for architecture */
    RAX_ERR_STATE       = 11, /* invalid in current state */
    RAX_ERR_FAULT       = 12, /* unrecoverable guest fault */
    RAX_ERR_IO          = 13, /* host I/O error */
    RAX_ERR_FORMAT      = 14, /* malformed/incompatible serialized data */
    RAX_ERR_HOOK        = 15, /* hook registration error */
    RAX_ERR_UNSUPPORTED = 16, /* not supported by this build/arch */
    RAX_ERR_INTERNAL    = 17  /* internal error (recovered panic) */
} rax_status;

/* ===========================================================================
 * Architectures, backends, modes
 * ======================================================================== */
typedef enum rax_arch {
    RAX_ARCH_X86     = 1, /* x86 / x86-64 (bitness via RAX_MODE_16/32/64) */
    RAX_ARCH_ARM64   = 2, /* AArch64 (ARMv8-A 64-bit) */
    RAX_ARCH_ARM     = 3, /* AArch32 / ARMv7-A (ARM or Thumb) */
    RAX_ARCH_RISCV64 = 4, /* RV64GC; optional extensions via rax_engine_config.riscv_ext */
    RAX_ARCH_HEXAGON = 5, /* Qualcomm Hexagon */
    RAX_ARCH_CORTEXM = 6  /* ARM Cortex-M (Thumb-only) */
} rax_arch;

/* Backend selector (only the portable software emulator is exposed via C). */
#define RAX_BACKEND_DEFAULT  0
#define RAX_BACKEND_EMULATOR 1

/* CPU mode flags (bitmask) passed to rax_engine_open / rax_engine_config. */
#define RAX_MODE_16            (1u << 0) /* x86 16-bit real mode */
#define RAX_MODE_32            (1u << 1) /* x86 32-bit protected mode */
#define RAX_MODE_64            (1u << 2) /* x86 64-bit long mode (default) */
#define RAX_MODE_ARM           (1u << 3) /* AArch32 ARM state (default) */
#define RAX_MODE_THUMB         (1u << 4) /* AArch32 Thumb state */
#define RAX_MODE_BIG_ENDIAN    (1u << 5) /* big-endian (where applicable) */
#define RAX_MODE_LITTLE_ENDIAN (1u << 6) /* little-endian (default) */

/* Open flags. */
#define RAX_OPEN_NO_DEFAULT_STATE (1u << 0) /* do not install a default state */

/* RISC-V extension flags for rax_engine_config.riscv_ext.
 * These opt into runtime extensions not enabled by the default RV64GC profile.
 */
#define RAX_RISCV_EXT_ZCMP      (1ull << 0) /* Zcmp compressed push/pop/move */
#define RAX_RISCV_EXT_ZCMT      (1ull << 1) /* Zcmt compressed table jumps */
#define RAX_RISCV_EXT_ZCLSD     (1ull << 2) /* Zclsd compressed load/store pairs */
#define RAX_RISCV_EXT_ZILSD     (1ull << 3) /* Zilsd load/store pairs */
#define RAX_RISCV_EXT_XHAZARD3  (1ull << 4) /* Hazard3/RP2350 custom hints/ops */
#define RAX_RISCV_EXT_XANDES    (1ull << 5) /* Andes custom instructions */
#define RAX_RISCV_EXT_XTHEAD    (1ull << 6) /* T-Head/Xuantie custom instructions */
#define RAX_RISCV_EXT_XIDA_SLTW (1ull << 7) /* IDA-compatible non-standard sltw */
#define RAX_RISCV_EXT_SUPPORTED \
    (RAX_RISCV_EXT_ZCMP | RAX_RISCV_EXT_ZCMT | RAX_RISCV_EXT_ZCLSD | \
     RAX_RISCV_EXT_ZILSD | RAX_RISCV_EXT_XHAZARD3 | RAX_RISCV_EXT_XANDES | \
     RAX_RISCV_EXT_XTHEAD | RAX_RISCV_EXT_XIDA_SLTW)

/* Memory protection flags (bitmask). */
#define RAX_PROT_NONE  0u
#define RAX_PROT_READ  (1u << 0)
#define RAX_PROT_WRITE (1u << 1)
#define RAX_PROT_EXEC  (1u << 2)
#define RAX_PROT_ALL   (RAX_PROT_READ | RAX_PROT_WRITE | RAX_PROT_EXEC)

/* Translation access intent for rax_mem_translate. */
#define RAX_ACCESS_READ  0
#define RAX_ACCESS_WRITE 1
#define RAX_ACCESS_EXEC  2

/* Hook type bits (informational; typed registration functions below). */
#define RAX_HOOK_CODE       (1u << 0)
#define RAX_HOOK_BLOCK      (1u << 1)
#define RAX_HOOK_INTR       (1u << 2)
#define RAX_HOOK_IO_IN      (1u << 3)
#define RAX_HOOK_IO_OUT     (1u << 4)
#define RAX_HOOK_MMIO_READ  (1u << 5)
#define RAX_HOOK_MMIO_WRITE (1u << 6)
#define RAX_HOOK_INVALID    (1u << 7)
#define RAX_HOOK_MEM_READ   (1u << 8)  /* per-access data read  */
#define RAX_HOOK_MEM_WRITE  (1u << 9)  /* per-access data write */
#define RAX_HOOK_MEM_FETCH  (1u << 10) /* per-access instruction fetch */

/* `kind` value passed to a memory hook callback (rax_mem_cb). */
#define RAX_MEM_READ  0
#define RAX_MEM_WRITE 1
#define RAX_MEM_FETCH 2

/* Stop reasons reported in rax_exit.reason. */
#define RAX_STOP_NONE        0
#define RAX_STOP_COUNT       1  /* instruction count limit reached */
#define RAX_STOP_UNTIL       2  /* PC reached the `until` address */
#define RAX_STOP_TIMEOUT     3  /* wall-clock timeout */
#define RAX_STOP_STOPPED     4  /* rax_emu_stop() was called */
#define RAX_STOP_HLT         5  /* guest halted */
#define RAX_STOP_IO_IN       6  /* unserviced port input */
#define RAX_STOP_IO_OUT      7  /* unserviced port output */
#define RAX_STOP_MMIO_READ   8  /* unserviced MMIO read */
#define RAX_STOP_MMIO_WRITE  9  /* unserviced MMIO write */
#define RAX_STOP_EXCEPTION   10 /* unhandled CPU exception / software interrupt */
#define RAX_STOP_INTERRUPT   11 /* (reserved) external interrupt */
#define RAX_STOP_SHUTDOWN    12 /* guest requested shutdown */
#define RAX_STOP_DEBUG       13 /* debug/breakpoint event */
#define RAX_STOP_ERROR       14 /* unrecoverable error (see rax_exit.status) */

/* Sentinel "no until-address" value for rax_emu_start(). */
#define RAX_NO_ADDR ((uint64_t)0xFFFFFFFFFFFFFFFFULL)

/* ===========================================================================
 * Opaque engine handle
 * ======================================================================== */
typedef struct rax_engine rax_engine;

/* ===========================================================================
 * Structures (ABI-stable)
 * ======================================================================== */

/* Full open configuration. Set `size = sizeof(rax_engine_config)`. */
typedef struct rax_engine_config {
    uint32_t size;      /* sizeof(rax_engine_config), for forward-compat */
    int32_t  arch;      /* rax_arch */
    uint32_t mode;      /* RAX_MODE_* */
    int32_t  backend;   /* RAX_BACKEND_* (0 = default) */
    uint64_t mem_base;  /* initial region base (page-aligned) */
    uint64_t mem_size;  /* initial region size (page-aligned; 0 = default) */
    uint32_t mem_perms; /* RAX_PROT_* for the initial region */
    uint32_t flags;     /* RAX_OPEN_* */
    uint64_t riscv_ext; /* RAX_RISCV_EXT_* for RAX_ARCH_RISCV64 */
} rax_engine_config;

/* A mapped memory region (rax_mem_regions). */
typedef struct rax_mem_region {
    uint64_t base;
    uint64_t size;
    uint32_t perms;     /* RAX_PROT_* */
    uint32_t _reserved;
} rax_mem_region;

/* Description of why execution stopped (rax_emu_last_exit). */
typedef struct rax_exit {
    int32_t  reason;    /* RAX_STOP_* */
    int32_t  status;    /* rax_status if reason == RAX_STOP_ERROR */
    uint64_t address;   /* PC at stop, or fault/MMIO address */
    uint64_t value;     /* I/O/MMIO value; retired steps for control stops */
    uint32_t size;      /* access size in bytes (I/O / MMIO) */
    uint32_t port;      /* I/O port (IO_IN / IO_OUT) */
    uint32_t intno;     /* interrupt/exception vector */
    uint32_t _reserved;
} rax_exit;

/* Typed execution-fault query, added in ABI 1.4. Existing structs are unchanged. */
#define RAX_FAULT_INFO_VERSION 1u
#define RAX_FAULT_NONE 0u
#define RAX_FAULT_UNMAPPED 1u
#define RAX_FAULT_PERMISSION 2u
#define RAX_FAULT_INVALID_INSTRUCTION 3u
#define RAX_FAULT_OTHER 4u
#define RAX_FAULT_ACCESS_NONE 0u
#define RAX_FAULT_ACCESS_READ 1u
#define RAX_FAULT_ACCESS_WRITE 2u
#define RAX_FAULT_ACCESS_FETCH 3u
#define RAX_FAULT_ADDRESS_VALID 1u

typedef struct rax_fault_info {
    uint32_t struct_size; /* caller: sizeof(rax_fault_info); output: v1 size */
    uint32_t version;     /* caller: RAX_FAULT_INFO_VERSION */
    uint32_t kind;        /* RAX_FAULT_* */
    uint32_t access;      /* RAX_FAULT_ACCESS_* */
    uint64_t pc;          /* instruction start */
    uint64_t address;     /* first inaccessible byte, valid only with flag */
    uint32_t size;        /* inaccessible access width in bytes; 0 = unknown */
    uint32_t flags;       /* RAX_FAULT_ADDRESS_VALID; other bits zero */
    uint64_t retired_instructions; /* successful steps in the last run/step */
} rax_fault_info;

/* Retained across host memory/register queries; reset by the next run/step or
 * engine reset. Callable from the invalid hook. Does not clear error text.
 * Initialize struct_size and version. NULL/short output returns ARG, unknown
 * version returns UNSUPPORTED; output remains unchanged on failure. Writes
 * exactly the v1 size, preserving any caller-owned extension tail.
 * Only UNMAPPED names missing physical backing eligible for external fault-in.
 * Guest translation/decoder/internal faults must not trigger guessed mappings. */
RAX_API rax_status rax_emu_last_fault(const rax_engine *engine, rax_fault_info *out);

/* ===========================================================================
 * Hook callback types
 *
 * Callbacks receive the engine handle and may call back into the API freely
 * (read/write registers and memory, request a stop via rax_emu_stop).
 * ======================================================================== */
typedef void     (*rax_code_cb)(rax_engine *e, uint64_t address, uint32_t size, void *user);
typedef void     (*rax_intr_cb)(rax_engine *e, uint32_t intno, void *user);
typedef uint64_t (*rax_io_in_cb)(rax_engine *e, uint32_t port, uint32_t size, void *user);
typedef void     (*rax_io_out_cb)(rax_engine *e, uint32_t port, uint32_t size, uint64_t value, void *user);
typedef uint64_t (*rax_mmio_read_cb)(rax_engine *e, uint64_t addr, uint32_t size, void *user);
typedef void     (*rax_mmio_write_cb)(rax_engine *e, uint64_t addr, uint32_t size, uint64_t value, void *user);
/* Return non-zero if handled (continue), zero to stop. */
typedef int      (*rax_invalid_cb)(rax_engine *e, uint64_t address, void *user);
/* Per-access memory hook: `kind` is RAX_MEM_READ/WRITE/FETCH; `value` is the
 * data read/written (low 8 bytes, little-endian; 0 for fetch). Fires once per
 * access after the step attempt, including completed REP elements before a
 * later fault. A callback does not prove instruction retirement. */
typedef void     (*rax_mem_cb)(rax_engine *e, int kind, uint64_t addr, uint32_t size, uint64_t value, void *user);

/* ===========================================================================
 * Library globals
 * ======================================================================== */

/* Packed version (major<<16 | minor<<8 | patch); fills out-params if non-NULL. */
RAX_API uint32_t    rax_version(uint32_t *major, uint32_t *minor, uint32_t *patch);
RAX_API const char *rax_version_string(void);
/* Static description for a status code (never NULL). */
RAX_API const char *rax_strerror(int status);

/* ===========================================================================
 * Engine lifecycle
 * ======================================================================== */

/* Open an engine for `arch` in `mode`, pre-mapping a default RAM region.
 * Writes a non-NULL handle to *out on success. */
RAX_API rax_status rax_engine_open(int arch, uint32_t mode, rax_engine **out);
/* Open from a full configuration struct. */
RAX_API rax_status rax_engine_open_config(const rax_engine_config *cfg, rax_engine **out);
/* Close an engine and release all resources. NULL is a no-op. */
RAX_API void       rax_engine_close(rax_engine *engine);
/* Reset to power-on architectural state; memory mappings/contents preserved. */
RAX_API rax_status rax_engine_reset(rax_engine *engine);

/* Queries. */
RAX_API int      rax_engine_arch(const rax_engine *engine);             /* rax_arch, or <0 */
RAX_API uint32_t rax_engine_mode(const rax_engine *engine);             /* normalized mode */
RAX_API int      rax_engine_supports_stepping(const rax_engine *engine);/* 1/0 */
/* Copies the latest detailed error message (NUL-terminated, truncated to cap).
 * Returns full length excluding NUL, or <0 on bad handle. */
RAX_API int      rax_engine_errmsg(const rax_engine *engine, char *buf, size_t cap);

/* ===========================================================================
 * Memory
 * ======================================================================== */

/* Map / unmap / change permissions. Addresses and sizes are page-aligned
 * (4096). At least one region must remain mapped at all times. */
RAX_API rax_status rax_mem_map(rax_engine *engine, uint64_t addr, uint64_t size, uint32_t perms);
RAX_API rax_status rax_mem_unmap(rax_engine *engine, uint64_t addr, uint64_t size);
RAX_API rax_status rax_mem_protect(rax_engine *engine, uint64_t addr, uint64_t size, uint32_t perms);

/* Physical (host/debugger) access: succeeds for any mapped range regardless of
 * permissions. */
RAX_API rax_status rax_mem_write(rax_engine *engine, uint64_t addr, const void *bytes, size_t len);
RAX_API rax_status rax_mem_read(rax_engine *engine, uint64_t addr, void *bytes, size_t len);

/* Virtual access: translates through the current paging state, page by page. */
RAX_API rax_status rax_mem_write_virt(rax_engine *engine, uint64_t vaddr, const void *bytes, size_t len);
RAX_API rax_status rax_mem_read_virt(rax_engine *engine, uint64_t vaddr, void *bytes, size_t len);

/* Translate a virtual address (access: RAX_ACCESS_*) to physical, into *paddr. */
RAX_API rax_status rax_mem_translate(rax_engine *engine, uint64_t vaddr, int access, uint64_t *paddr);

/* Enumerate regions: if `out` is non-NULL, up to *count are written; *count is
 * always set to the total. */
RAX_API rax_status rax_mem_regions(const rax_engine *engine, rax_mem_region *out, size_t *count);

/* ===========================================================================
 * Registers (see register id macros at the end of this header)
 * ======================================================================== */

/* Natural byte width of a register for `arch`, or 0 if invalid. */
RAX_API size_t     rax_reg_size(int arch, int regid);
/* Read into `value` (>= rax_reg_size bytes); writes the count to *out_size. */
RAX_API rax_status rax_reg_read(rax_engine *engine, int regid, void *value, size_t *out_size);
/* Write from `value` (>= rax_reg_size bytes). */
RAX_API rax_status rax_reg_write(rax_engine *engine, int regid, const void *value);
/* Convenience for integer registers of width <= 8. */
RAX_API rax_status rax_reg_read_u64(rax_engine *engine, int regid, uint64_t *value);
RAX_API rax_status rax_reg_write_u64(rax_engine *engine, int regid, uint64_t value);

/* ===========================================================================
 * Execution control
 * ======================================================================== */

/* Run from `begin` until a stop condition:
 *   - `count` instructions retired (0 = unlimited),
 *   - PC reaches `until` (RAX_NO_ADDR = none),
 *   - `timeout_us` microseconds elapse (0 = none),
 *   - rax_emu_stop() called from a hook,
 *   - the guest halts / an unhandled exit or fault occurs.
 * Returns RAX_OK for any clean stop (inspect rax_emu_last_exit), or an error
 * status for an unrecoverable fault.
 *
 * Instruction-granular control (count/until/timeout and code/block hooks)
 * requires a stepping-capable backend (rax_engine_supports_stepping). */
RAX_API rax_status rax_emu_start(rax_engine *engine, uint64_t begin, uint64_t until,
                                 uint64_t timeout_us, uint64_t count);
/* Step `count` instructions from the current PC (0 treated as 1); writes the
 * number executed to *executed if non-NULL. */
RAX_API rax_status rax_emu_step(rax_engine *engine, uint64_t count, uint64_t *executed);
/* Request a stop at the next safe point (call from a hook). */
RAX_API rax_status rax_emu_stop(rax_engine *engine);
/* Copy the most recent stop/exit descriptor into *out. */
RAX_API rax_status rax_emu_last_exit(const rax_engine *engine, rax_exit *out);
/* Total number of instructions retired by the vCPU. */
RAX_API uint64_t   rax_emu_icount(const rax_engine *engine);

/* Interrupts. */
RAX_API rax_status rax_interrupt(rax_engine *engine, uint32_t vector); /* RAX_ERR_STATE if masked */
RAX_API rax_status rax_nmi(rax_engine *engine);
RAX_API int        rax_can_interrupt(const rax_engine *engine);       /* 1/0 */

/* ===========================================================================
 * Hooks
 * ======================================================================== */

/* For range hooks, begin > end means "all addresses". out_id (if non-NULL)
 * receives a handle for rax_hook_del. */
RAX_API rax_status rax_hook_add_code(rax_engine *engine, uint64_t begin, uint64_t end,
                                     rax_code_cb cb, void *user, uint32_t *out_id);
RAX_API rax_status rax_hook_add_block(rax_engine *engine, uint64_t begin, uint64_t end,
                                      rax_code_cb cb, void *user, uint32_t *out_id);
RAX_API rax_status rax_hook_add_intr(rax_engine *engine, rax_intr_cb cb, void *user, uint32_t *out_id);
RAX_API rax_status rax_hook_add_io_in(rax_engine *engine, rax_io_in_cb cb, void *user, uint32_t *out_id);
RAX_API rax_status rax_hook_add_io_out(rax_engine *engine, rax_io_out_cb cb, void *user, uint32_t *out_id);
RAX_API rax_status rax_hook_add_mmio_read(rax_engine *engine, rax_mmio_read_cb cb, void *user, uint32_t *out_id);
RAX_API rax_status rax_hook_add_mmio_write(rax_engine *engine, rax_mmio_write_cb cb, void *user, uint32_t *out_id);
RAX_API rax_status rax_hook_add_invalid(rax_engine *engine, rax_invalid_cb cb, void *user, uint32_t *out_id);
/* Per-access memory hook. `types` is a mask of RAX_HOOK_MEM_READ/WRITE/FETCH;
 * `[begin, end]` filters by address (begin > end ⇒ all). Requires a backend
 * that records memory accesses (x86-64 today). */
RAX_API rax_status rax_hook_add_mem(rax_engine *engine, uint32_t types, uint64_t begin, uint64_t end,
                                    rax_mem_cb cb, void *user, uint32_t *out_id);
RAX_API rax_status rax_hook_del(rax_engine *engine, uint32_t hook_id);

/* ===========================================================================
 * Context (snapshot) save / restore
 * ======================================================================== */

/* Save a complete context (CPU + extended state + all memory) to a caller
 * buffer. Two-call: pass buf == NULL to learn *out_len, then call again with a
 * sufficiently large buffer. Returns RAX_ERR_BOUNDS if buf != NULL but cap is
 * too small. */
RAX_API rax_status rax_context_save(const rax_engine *engine, void *buf, size_t cap, size_t *out_len);
/* Restore a context previously produced by rax_context_save. */
RAX_API rax_status rax_context_restore(rax_engine *engine, const void *data, size_t len);

/* ===========================================================================
 * Register ids
 *
 * Each architecture has its own id space. Family macros give complete coverage;
 * named aliases below are conveniences that evaluate to the same numbers.
 * Values are transferred little-endian, sized to the register's natural width
 * (rax_reg_size). Vector registers are raw byte arrays.
 * ======================================================================== */

/* ---- x86 / x86-64 -------------------------------------------------------- */
/* GPR index order: AX,CX,DX,BX,SP,BP,SI,DI, R8..R15, R16..R31 (0..31). */
#define RAX_X86_GPR64(i)     (0x0100 + (i)) /* RAX..R31  (8 bytes) */
#define RAX_X86_GPR32(i)     (0x0200 + (i)) /* EAX..R31D (4 bytes) */
#define RAX_X86_GPR16(i)     (0x0300 + (i)) /* AX..R31W  (2 bytes) */
#define RAX_X86_GPR8L(i)     (0x0400 + (i)) /* AL..R31B  (1 byte)  */
#define RAX_X86_GPR8H(i)     (0x0500 + (i)) /* AH,CH,DH,BH (i in 0..3) */
#define RAX_X86_SEG_SEL(i)   (0x0600 + (i)) /* ES,CS,SS,DS,FS,GS selector (2) */
#define RAX_X86_SEG_BASE(i)  (0x0700 + (i)) /* segment base (8) */
#define RAX_X86_SEG_LIMIT(i) (0x0800 + (i)) /* segment limit (4) */
#define RAX_X86_CR(i)        (0x0900 + (i)) /* CR0,CR2,CR3,CR4,CR8 (8) */
#define RAX_X86_DR(i)        (0x0A00 + (i)) /* DR0..DR3,DR6,DR7 (8) */
#define RAX_X86_XMM(i)       (0x0B00 + (i)) /* XMM0..31 (16 bytes) */
#define RAX_X86_YMM(i)       (0x0C00 + (i)) /* YMM0..31 (32 bytes) */
#define RAX_X86_ZMM(i)       (0x0D00 + (i)) /* ZMM0..31 (64 bytes) */
#define RAX_X86_K(i)         (0x0E00 + (i)) /* K0..7 mask regs (8 bytes) */
#define RAX_X86_MM(i)        (0x0F00 + (i)) /* MM0..7 MMX (8 bytes) */

#define RAX_X86_REG_RIP      0x0010
#define RAX_X86_REG_EIP      0x0011
#define RAX_X86_REG_RFLAGS   0x0012
#define RAX_X86_REG_EFLAGS   0x0013
#define RAX_X86_REG_FLAGS    0x0014

#define RAX_X86_REG_EFER         0x1000
#define RAX_X86_REG_STAR         0x1001
#define RAX_X86_REG_LSTAR        0x1002
#define RAX_X86_REG_CSTAR        0x1003
#define RAX_X86_REG_FMASK        0x1004
#define RAX_X86_REG_SYSENTER_CS  0x1006
#define RAX_X86_REG_SYSENTER_ESP 0x1007
#define RAX_X86_REG_SYSENTER_EIP 0x1008
#define RAX_X86_REG_FS_BASE      0x1009
#define RAX_X86_REG_GS_BASE      0x100A
#define RAX_X86_REG_GDT_BASE     0x1100
#define RAX_X86_REG_GDT_LIMIT    0x1101
#define RAX_X86_REG_IDT_BASE     0x1102
#define RAX_X86_REG_IDT_LIMIT    0x1103
#define RAX_X86_REG_LDTR_SEL     0x1104
#define RAX_X86_REG_LDTR_BASE    0x1105
#define RAX_X86_REG_LDTR_LIMIT   0x1106
#define RAX_X86_REG_TR_SEL       0x1107
#define RAX_X86_REG_TR_BASE      0x1108
#define RAX_X86_REG_TR_LIMIT     0x1109

/* 64-bit GPR named aliases. */
#define RAX_X86_REG_RAX RAX_X86_GPR64(0)
#define RAX_X86_REG_RCX RAX_X86_GPR64(1)
#define RAX_X86_REG_RDX RAX_X86_GPR64(2)
#define RAX_X86_REG_RBX RAX_X86_GPR64(3)
#define RAX_X86_REG_RSP RAX_X86_GPR64(4)
#define RAX_X86_REG_RBP RAX_X86_GPR64(5)
#define RAX_X86_REG_RSI RAX_X86_GPR64(6)
#define RAX_X86_REG_RDI RAX_X86_GPR64(7)
#define RAX_X86_REG_R8  RAX_X86_GPR64(8)
#define RAX_X86_REG_R9  RAX_X86_GPR64(9)
#define RAX_X86_REG_R10 RAX_X86_GPR64(10)
#define RAX_X86_REG_R11 RAX_X86_GPR64(11)
#define RAX_X86_REG_R12 RAX_X86_GPR64(12)
#define RAX_X86_REG_R13 RAX_X86_GPR64(13)
#define RAX_X86_REG_R14 RAX_X86_GPR64(14)
#define RAX_X86_REG_R15 RAX_X86_GPR64(15)
/* 32-bit GPR aliases (common ones). */
#define RAX_X86_REG_EAX RAX_X86_GPR32(0)
#define RAX_X86_REG_ECX RAX_X86_GPR32(1)
#define RAX_X86_REG_EDX RAX_X86_GPR32(2)
#define RAX_X86_REG_EBX RAX_X86_GPR32(3)
#define RAX_X86_REG_ESP RAX_X86_GPR32(4)
#define RAX_X86_REG_EBP RAX_X86_GPR32(5)
#define RAX_X86_REG_ESI RAX_X86_GPR32(6)
#define RAX_X86_REG_EDI RAX_X86_GPR32(7)
/* 16-bit and 8-bit aliases. */
#define RAX_X86_REG_AX  RAX_X86_GPR16(0)
#define RAX_X86_REG_CX  RAX_X86_GPR16(1)
#define RAX_X86_REG_DX  RAX_X86_GPR16(2)
#define RAX_X86_REG_BX  RAX_X86_GPR16(3)
#define RAX_X86_REG_AL  RAX_X86_GPR8L(0)
#define RAX_X86_REG_CL  RAX_X86_GPR8L(1)
#define RAX_X86_REG_DL  RAX_X86_GPR8L(2)
#define RAX_X86_REG_BL  RAX_X86_GPR8L(3)
#define RAX_X86_REG_AH  RAX_X86_GPR8H(0)
#define RAX_X86_REG_CH  RAX_X86_GPR8H(1)
#define RAX_X86_REG_DH  RAX_X86_GPR8H(2)
#define RAX_X86_REG_BH  RAX_X86_GPR8H(3)
/* Segment selector aliases. */
#define RAX_X86_REG_ES  RAX_X86_SEG_SEL(0)
#define RAX_X86_REG_CS  RAX_X86_SEG_SEL(1)
#define RAX_X86_REG_SS  RAX_X86_SEG_SEL(2)
#define RAX_X86_REG_DS  RAX_X86_SEG_SEL(3)
#define RAX_X86_REG_FS  RAX_X86_SEG_SEL(4)
#define RAX_X86_REG_GS  RAX_X86_SEG_SEL(5)
/* Control register aliases. */
#define RAX_X86_REG_CR0 RAX_X86_CR(0)
#define RAX_X86_REG_CR2 RAX_X86_CR(2)
#define RAX_X86_REG_CR3 RAX_X86_CR(3)
#define RAX_X86_REG_CR4 RAX_X86_CR(4)
#define RAX_X86_REG_CR8 RAX_X86_CR(8)

/* ---- common scalar ids (shared encoding; per-arch validity differs) ------ */
#define RAX_REG_SP      0x0010
#define RAX_REG_PC      0x0011
#define RAX_REG_PSTATE  0x0012 /* AArch64 PSTATE / AArch32 CPSR / Cortex-M xPSR */
#define RAX_REG_LR      0x0013
#define RAX_REG_SPSR    0x0014
#define RAX_REG_FPCR    0x0020
#define RAX_REG_FPSR    0x0021
#define RAX_REG_FPSCR   0x0022
#define RAX_REG_FCSR    0x0023
#define RAX_CM_REG_MSP       0x0030
#define RAX_CM_REG_PSP       0x0031
#define RAX_CM_REG_CONTROL   0x0032
#define RAX_CM_REG_PRIMASK   0x0033
#define RAX_CM_REG_FAULTMASK 0x0034
#define RAX_CM_REG_BASEPRI   0x0035

/* ---- AArch64 ------------------------------------------------------------- */
#define RAX_ARM64_X(i)  (0x0100 + (i)) /* X0..X30 (8 bytes) */
#define RAX_ARM64_V(i)  (0x0200 + (i)) /* V0..V31 (16 bytes) */
#define RAX_ARM64_REG_SP     RAX_REG_SP
#define RAX_ARM64_REG_PC     RAX_REG_PC
#define RAX_ARM64_REG_PSTATE RAX_REG_PSTATE
#define RAX_ARM64_REG_FPCR   RAX_REG_FPCR
#define RAX_ARM64_REG_FPSR   RAX_REG_FPSR

/* ---- AArch32 / ARMv7-A --------------------------------------------------- */
#define RAX_ARM_R(i)    (0x0100 + (i)) /* R0..R12 (4 bytes) */
#define RAX_ARM_S(i)    (0x0200 + (i)) /* S0..S31 (4 bytes) */
#define RAX_ARM_REG_SP   RAX_REG_SP
#define RAX_ARM_REG_LR   RAX_REG_LR
#define RAX_ARM_REG_PC   RAX_REG_PC
#define RAX_ARM_REG_CPSR RAX_REG_PSTATE
#define RAX_ARM_REG_SPSR RAX_REG_SPSR
#define RAX_ARM_REG_FPSCR RAX_REG_FPSCR

/* ---- Cortex-M ------------------------------------------------------------ */
#define RAX_CM_R(i)     (0x0100 + (i)) /* R0..R12 (4 bytes) */
#define RAX_CM_S(i)     (0x0200 + (i)) /* S0..S31 (4 bytes) */
#define RAX_CM_REG_LR    RAX_REG_LR
#define RAX_CM_REG_PC    RAX_REG_PC
#define RAX_CM_REG_XPSR  RAX_REG_PSTATE
#define RAX_CM_REG_FPSCR RAX_REG_FPSCR

/* ---- RISC-V (RV64) ------------------------------------------------------- */
#define RAX_RISCV_X(i)  (0x0100 + (i)) /* x0..x31 (8 bytes; x0 is read-only 0) */
#define RAX_RISCV_F(i)  (0x0200 + (i)) /* f0..f31 (8 bytes) */
#define RAX_RISCV_REG_PC   RAX_REG_PC
#define RAX_RISCV_REG_FCSR RAX_REG_FCSR

/* ---- Hexagon ------------------------------------------------------------- */
#define RAX_HEX_R(i)    (0x0100 + (i)) /* R0..R31 (4 bytes) */
#define RAX_HEX_V(i)    (0x0200 + (i)) /* V0..V31 (128 bytes) */
#define RAX_HEX_C(i)    (0x0300 + (i)) /* control regs (4 bytes); PC = C9 */
#define RAX_HEX_P(i)    (0x0400 + (i)) /* P0..P3 predicates (1 byte) */
#define RAX_HEX_Q(i)    (0x0500 + (i)) /* Q0..Q3 vector predicates (16 bytes) */
#define RAX_HEX_REG_PC  RAX_HEX_C(9)

/* ===========================================================================
 * Static instruction decode (since API 1.2)
 *
 * A pure, stateless disassembly of a single instruction — no engine, no memory
 * map, no execution, no side effects. Backed by the same comprehensive x86 and
 * ARM (and RISC-V / Hexagon) decoders the emulator uses, exposed here so tools
 * can recover instruction length and control-flow semantics statically.
 * ======================================================================== */

/* Control-flow class of a decoded instruction (rax_decoded.flow). */
#define RAX_FLOW_FALLTHROUGH    0  /* no branch; execution continues to next insn */
#define RAX_FLOW_BRANCH         1  /* unconditional direct jump; `target` valid    */
#define RAX_FLOW_COND_BRANCH    2  /* conditional branch; `target`+`fallthrough`    */
#define RAX_FLOW_INDIRECT_JUMP  3  /* computed jump; no static target               */
#define RAX_FLOW_CALL           4  /* direct call; `target` valid                   */
#define RAX_FLOW_INDIRECT_CALL  5  /* computed call; no static target               */
#define RAX_FLOW_RETURN         6  /* return from function                          */
#define RAX_FLOW_TRAP           7  /* trap / undefined / exception-raising          */
#define RAX_FLOW_SYSCALL        8  /* system call                                   */
#define RAX_FLOW_UNKNOWN        9  /* decoded, but control flow not classified      */

/* Result of rax_decode(). ABI-stable: trailing `_reserved` is for extension. */
typedef struct rax_decoded {
    uint32_t size;        /* instruction length in bytes (0 if !valid)            */
    int32_t  flow;        /* one of RAX_FLOW_*                                     */
    uint32_t is_indirect; /* 1 if the branch/call target is computed at runtime   */
    uint32_t has_target;  /* 1 if `target` holds a resolved direct target         */
    uint64_t target;      /* absolute direct branch/call target (when has_target) */
    uint64_t fallthrough; /* not-taken address for a conditional branch           */
    uint32_t valid;       /* 1 if the bytes decoded to a valid instruction        */
    uint32_t _reserved;
} rax_decoded;

/* Decode ONE instruction at virtual address `pc` from `bytes[0..len)` for the
 * given architecture and CPU mode (same `arch`/`mode` values as
 * rax_engine_open). Fills *out. Returns RAX_OK when the call is well-formed —
 * inspect out->valid to see whether the bytes actually decoded (an undecodable
 * or truncated instruction yields RAX_OK with out->valid == 0). Returns an
 * error status only for a bad argument (NULL out/bytes, unsupported arch). */
RAX_API rax_status rax_decode(int arch, uint32_t mode, uint64_t pc,
                              const void *bytes, size_t len, rax_decoded *out);

/* Versioned static instruction metadata. ABI 1.5+, initially x86 16/32/64.
 * No engine or execution support is implied. All strings are lower-case ASCII,
 * NUL-terminated inline storage. Invalid/truncated bytes return OK, valid=0.
 * Unsupported architecture returns ERR_ARCH. Invalid mode returns ERR_MODE.
 * Caller initializes struct_size and abi_version; too-small/version mismatch
 * returns ERR_ARG without touching output. Larger caller tails are untouched.
 * Operand metadata describes explicit operands, not complete semantic effects.
 * Memory displacement is unsigned two's-complement, reduced to address_bits;
 * for IP-relative memory, displacement is the resolved absolute address and
 * base is empty. A segment base must still be added according to guest mode.
 */
#define RAX_INSTRUCTION_INFO_VERSION 1u
#define RAX_INSTRUCTION_BASIC_COMPLETE 1u
#define RAX_INSTRUCTION_OPERANDS_COMPLETE 2u
#define RAX_INSTRUCTION_UNREPRESENTED 4u /* encoding not exported by native metadata */
#define RAX_OPERAND_REGISTER 1u
#define RAX_OPERAND_MEMORY 2u
#define RAX_OPERAND_IMMEDIATE 3u
#define RAX_OPERAND_TARGET 4u
#define RAX_OPERAND_READ 1u
#define RAX_OPERAND_WRITE 2u
#define RAX_OPERAND_CONDITIONAL 4u

typedef struct rax_instruction_operand {
    uint32_t kind, access, width_bits, address_bits;
    char reg[16], base[16], index[16], segment[8];
    uint32_t scale, _reserved;
    uint64_t displacement, value;
} rax_instruction_operand;

typedef struct rax_instruction_info_t {
    uint32_t struct_size, abi_version;
    rax_decoded decoded;
    char mnemonic[32];
    uint32_t flags, operand_count;
    int32_t stack_pointer_increment; /* 0 if not a fixed stack adjustment */
    uint32_t _reserved;
    rax_instruction_operand operands[5];
} rax_instruction_info_t;

RAX_API rax_status rax_instruction_info(int arch, uint32_t mode, uint64_t pc,
    const void *bytes, size_t len, rax_instruction_info_t *out);

/* ===========================================================================
 * Stateless instruction-effect analysis (since API 1.3)
 *
 * This is a producer-neutral, pointer-free projection of the SMIR lift for one
 * instruction. It includes rax_decode's flow result plus normalized register
 * and memory effects. The library owns no memory in the returned data: callers
 * provide the optional effect array and may use the two-call sizing form.
 *
 * Rich effects are currently defined for x86-64, AArch64, RV64, and Hexagon.
 * Other modes may still produce a valid `decoded` member but set
 * RAX_ANALYSIS_UNSUPPORTED/RAX_ANALYSIS_PARTIAL.
 * ======================================================================== */

#define RAX_ANALYSIS_ABI_VERSION 1u

/* rax_analysis.flags */
#define RAX_ANALYSIS_VALID       (1u << 0) /* decoded.valid is true              */
#define RAX_ANALYSIS_HAS_SMIR    (1u << 1) /* a SMIR lift produced the effects   */
#define RAX_ANALYSIS_COMPLETE    (1u << 2) /* effect set is semantically complete */
#define RAX_ANALYSIS_PARTIAL     (1u << 3) /* useful effects, but not exhaustive */
#define RAX_ANALYSIS_UNSUPPORTED (1u << 4) /* no rich lifter for this insn/mode  */
#define RAX_ANALYSIS_TRUNCATED   (1u << 5) /* caller effect array was too small  */

/* rax_analysis_effect.kind */
#define RAX_EFFECT_REGISTER 1u
#define RAX_EFFECT_MEMORY   2u

/* rax_analysis_effect.access */
#define RAX_EFFECT_READ             (1u << 0)
#define RAX_EFFECT_WRITE            (1u << 1)
#define RAX_EFFECT_CONDITIONAL      (1u << 2)
#define RAX_EFFECT_ATOMIC           (1u << 3)
#define RAX_EFFECT_REPEATED         (1u << 4)
#define RAX_EFFECT_ORDERED          (1u << 5)
#define RAX_EFFECT_IMPLICIT         (1u << 6)
#define RAX_EFFECT_ADDRESS_COMPLETE (1u << 7)
#define RAX_EFFECT_VALUE_COMPLETE   (1u << 8)

/* rax_analysis_effect.value_kind */
#define RAX_VALUE_UNKNOWN  0u
#define RAX_VALUE_CONSTANT 1u
#define RAX_VALUE_REGISTER 2u

/* rax_analysis_effect.address_kind */
#define RAX_ADDRESS_NONE            0u
#define RAX_ADDRESS_UNKNOWN         1u
#define RAX_ADDRESS_ABSOLUTE        2u
#define RAX_ADDRESS_REGISTER        3u
#define RAX_ADDRESS_BASE_DISP       4u
#define RAX_ADDRESS_BASE_INDEX_DISP 5u
#define RAX_ADDRESS_PC_RELATIVE     6u
#define RAX_ADDRESS_GP_RELATIVE     7u
#define RAX_ADDRESS_SEGMENT_RELATIVE 8u

/* Architecture-neutral condition-code masks used by flags_{read,written,
 * undefined}. On x86 N/V mean SF/OF; on ARM they mean N/V. P and A are
 * x86-only. D is the x86 direction flag. */
#define RAX_FLAG_C (1u << 0)
#define RAX_FLAG_Z (1u << 1)
#define RAX_FLAG_N (1u << 2)
#define RAX_FLAG_V (1u << 3)
#define RAX_FLAG_P (1u << 4)
#define RAX_FLAG_A (1u << 5)
#define RAX_FLAG_D (1u << 6)
#define RAX_FLAG_NZCV       (RAX_FLAG_C | RAX_FLAG_Z | RAX_FLAG_N | RAX_FLAG_V)
#define RAX_FLAG_ARITHMETIC (RAX_FLAG_NZCV | RAX_FLAG_P | RAX_FLAG_A)

/* One normalized register or data-memory effect. Ordinary instruction fetch
 * and sequential PC advance are represented by `decoded` rather than repeated
 * as effects. All register fields use the
 * architecture-specific stable RAX_* register-id space above; -1 means absent.
 * `width_bits == 0` means the lift did not expose a precise width. For a
 * register write or memory store, value_kind may prove a direct constant or a
 * direct register copy. Address fields are meaningful according to
 * address_kind. Reserved words are zero and must be ignored. */
typedef struct rax_analysis_effect {
    uint32_t struct_size; /* sizeof(rax_analysis_effect) */
    uint16_t abi_version; /* RAX_ANALYSIS_ABI_VERSION */
    uint16_t kind;        /* RAX_EFFECT_REGISTER/MEMORY */
    uint32_t access;      /* RAX_EFFECT_* bitmask */
    int32_t  reg;         /* affected register, or -1 */
    uint32_t width_bits;
    uint32_t value_kind;  /* RAX_VALUE_* */
    int32_t  source_reg;  /* RAX_VALUE_REGISTER source, or -1 */
    uint32_t address_kind;/* RAX_ADDRESS_* */
    int32_t  base_reg;
    int32_t  index_reg;
    int32_t  segment_reg;
    uint32_t scale;
    uint64_t value;       /* RAX_VALUE_CONSTANT */
    uint64_t address;     /* resolved absolute address when available */
    int64_t  displacement;
    uint64_t _reserved[2];
} rax_analysis_effect;

/* Fixed summary. `effect_count` is the number copied; required_effect_count is
 * the full count. struct_size and abi_version describe the library output. */
typedef struct rax_analysis {
    uint32_t struct_size; /* sizeof(rax_analysis) */
    uint32_t abi_version; /* RAX_ANALYSIS_ABI_VERSION */
    rax_decoded decoded;
    uint32_t flags;       /* RAX_ANALYSIS_* */
    uint32_t effect_count;
    uint32_t required_effect_count;
    uint32_t flags_read;      /* RAX_FLAG_* */
    uint32_t flags_written;   /* RAX_FLAG_* */
    uint32_t flags_undefined; /* RAX_FLAG_* */
    uint32_t smir_op_count;
    uint32_t _reserved0;
    uint64_t _reserved[4];
} rax_analysis;

/* Analyze ONE instruction. `out` and `out_effect_count` are required.
 *
 * Size query: pass effects == NULL and effect_cap == 0; RAX_OK is returned and
 * *out_effect_count/required_effect_count receive the required count.
 *
 * Fill: pass an array of effect_cap records. An undersized non-NULL array is
 * filled with a deterministic prefix, sets RAX_ANALYSIS_TRUNCATED, and returns
 * RAX_ERR_BOUNDS. A NULL array with nonzero capacity is RAX_ERR_ARG. */
RAX_API rax_status rax_analyze(int arch, uint32_t mode, uint64_t pc,
                               const void *bytes, size_t len,
                               rax_analysis *out,
                               rax_analysis_effect *effects, size_t effect_cap,
                               size_t *out_effect_count);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* RAX_H */
