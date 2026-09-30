/* Strict C11 compile-time consumer for the rax 1.5 user-mode and register ABI. */
#include <stddef.h>
#include <stdint.h>

#include "rax.h"

#ifdef __cplusplus
#  define RAX_TEST_STATIC_ASSERT(c, m) static_assert((c), m)
#else
#  define RAX_TEST_STATIC_ASSERT(c, m) _Static_assert((c), m)
#endif

RAX_TEST_STATIC_ASSERT(RAX_API_MAJOR == 1u, "unexpected ABI major");
RAX_TEST_STATIC_ASSERT(RAX_API_MINOR >= 5u, "user mode requires ABI 1.5+");
RAX_TEST_STATIC_ASSERT(RAX_MODE_USER == 0x80u, "user mode flag");
RAX_TEST_STATIC_ASSERT(RAX_STOP_SYSCALL == 15, "syscall stop reason");
RAX_TEST_STATIC_ASSERT(RAX_HOOK_SYSCALL == 0x800u, "syscall hook bit");
RAX_TEST_STATIC_ASSERT(RAX_SYSCALL_INSN_SYSCALL == 1u && RAX_SYSCALL_INSN_SYSENTER == 2u &&
                       RAX_SYSCALL_INSN_SVC == 3u && RAX_SYSCALL_INSN_ECALL == 4u,
                       "system-call instruction classes");

/* rax_exit keeps its 1.0 layout; SYSCALL stops reuse its fields. */
RAX_TEST_STATIC_ASSERT(sizeof(rax_exit) == 40u, "rax_exit ABI drift");
RAX_TEST_STATIC_ASSERT(offsetof(rax_exit, size) == 24u, "exit size offset");
RAX_TEST_STATIC_ASSERT(offsetof(rax_exit, port) == 28u, "exit port offset");
RAX_TEST_STATIC_ASSERT(offsetof(rax_exit, intno) == 32u, "exit intno offset");

RAX_TEST_STATIC_ASSERT(RAX_EXCEPTION_INFO_VERSION == 1u, "exception record version");
RAX_TEST_STATIC_ASSERT(sizeof(rax_exception_info) == 40u, "exception record size");
RAX_TEST_STATIC_ASSERT(offsetof(rax_exception_info, vector) == 8u, "exception vector offset");
RAX_TEST_STATIC_ASSERT(offsetof(rax_exception_info, flags) == 12u, "exception flags offset");
RAX_TEST_STATIC_ASSERT(offsetof(rax_exception_info, pc) == 16u, "exception pc offset");
RAX_TEST_STATIC_ASSERT(offsetof(rax_exception_info, return_pc) == 24u, "exception return offset");
RAX_TEST_STATIC_ASSERT(offsetof(rax_exception_info, syndrome) == 32u, "exception syndrome offset");

/* Register ids added in 1.5. */
RAX_TEST_STATIC_ASSERT(RAX_X86_ST(0) == 0x1200 && RAX_X86_ST(7) == 0x1207, "x87 stack ids");
RAX_TEST_STATIC_ASSERT(RAX_X86_REG_MXCSR == 0x1216, "MXCSR id");
RAX_TEST_STATIC_ASSERT(RAX_X86_SEG_ATTR(1) == 0x1301, "CS access-rights id");
RAX_TEST_STATIC_ASSERT(RAX_X86_REG_KERNEL_GS_BASE == 0x100B, "KERNEL_GS_BASE id");
RAX_TEST_STATIC_ASSERT(RAX_ARM64_REG_TPIDR_EL0 == 0x0400, "TPIDR_EL0 id");
RAX_TEST_STATIC_ASSERT(RAX_ARM64_REG_CNTV_CVAL_EL0 == 0x0412, "last AArch64 system register id");
RAX_TEST_STATIC_ASSERT(RAX_ARM_D(31) == 0x031F && RAX_ARM_Q(15) == 0x040F, "AArch32 D/Q ids");

static void on_syscall(rax_engine *engine, uint64_t pc, uint32_t insn, uint32_t imm, void *user)
{
    (void)pc;
    (void)insn;
    (void)imm;
    (void)user;
    (void)rax_reg_write_u64(engine, RAX_X86_REG_RAX, 0u);
}

rax_status user_abi_install(rax_engine *engine, uint32_t *id)
{
    return rax_hook_add_syscall(engine, on_syscall, NULL, id);
}

rax_status user_abi_query(const rax_engine *engine)
{
    rax_exception_info info = {0};
    info.struct_size = (uint32_t)sizeof(info);
    info.version = RAX_EXCEPTION_INFO_VERSION;
    return rax_emu_last_exception(engine, &info);
}

RAX_TEST_STATIC_ASSERT(RAX_API_MINOR >= 6u, "syscall query requires ABI 1.6+");
RAX_TEST_STATIC_ASSERT(sizeof(rax_syscall_info) == 40u, "syscall record size");
RAX_TEST_STATIC_ASSERT(offsetof(rax_syscall_info, pc) == 16u, "syscall PC offset");
RAX_TEST_STATIC_ASSERT(offsetof(rax_syscall_info, resume_pc) == 24u, "syscall resume offset");
RAX_TEST_STATIC_ASSERT(offsetof(rax_syscall_info, size) == 32u, "syscall length offset");

rax_status user_abi_syscall_query(const rax_engine *engine) {
    rax_syscall_info info = {0};
    info.struct_size = (uint32_t)sizeof(info);
    info.version = RAX_SYSCALL_INFO_VERSION;
    return rax_emu_last_syscall(engine, &info);
}
