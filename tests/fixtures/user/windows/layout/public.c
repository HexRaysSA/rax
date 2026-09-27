/* Compile-only checks for the public Windows guest structure layouts.
 * Expected byte offsets are consumed by src/user/windows/{context,layout}.rs.
 * Only fields declared by winnt.h/winternl.h are asserted here. */
#include <stddef.h>
#include <windows.h>
#include <winternl.h>

#define SIZE(type, expected) \
    _Static_assert(sizeof(type) == (expected), "rax-layout:sizeof(" #type ")")
#define OFFSET(type, field, expected) \
    _Static_assert(offsetof(type, field) == (expected), "rax-layout:" #type "." #field)

#if defined(__i386__)
SIZE(CONTEXT, 0x2cc);
SIZE(FLOATING_SAVE_AREA, 0x70);
SIZE(UNICODE_STRING, 0x08);
SIZE(LIST_ENTRY, 0x08);
OFFSET(CONTEXT, ContextFlags, 0x00);
OFFSET(CONTEXT, FloatSave, 0x1c);
OFFSET(CONTEXT, SegGs, 0x8c);
OFFSET(CONTEXT, SegFs, 0x90);
OFFSET(CONTEXT, SegEs, 0x94);
OFFSET(CONTEXT, SegDs, 0x98);
OFFSET(CONTEXT, Edi, 0x9c);
OFFSET(CONTEXT, Esi, 0xa0);
OFFSET(CONTEXT, Ebx, 0xa4);
OFFSET(CONTEXT, Edx, 0xa8);
OFFSET(CONTEXT, Ecx, 0xac);
OFFSET(CONTEXT, Eax, 0xb0);
OFFSET(CONTEXT, Ebp, 0xb4);
OFFSET(CONTEXT, Eip, 0xb8);
OFFSET(CONTEXT, SegCs, 0xbc);
OFFSET(CONTEXT, EFlags, 0xc0);
OFFSET(CONTEXT, Esp, 0xc4);
OFFSET(CONTEXT, SegSs, 0xc8);
OFFSET(CONTEXT, ExtendedRegisters, 0xcc);
OFFSET(NT_TIB, ExceptionList, 0x00);
OFFSET(NT_TIB, StackBase, 0x04);
OFFSET(NT_TIB, StackLimit, 0x08);
OFFSET(NT_TIB, FiberData, 0x10);
OFFSET(NT_TIB, Self, 0x18);
OFFSET(TEB, ProcessEnvironmentBlock, 0x30);
OFFSET(TEB, TlsSlots, 0xe10);
OFFSET(TEB, ReservedForOle, 0xf80);
OFFSET(TEB, TlsExpansionSlots, 0xf94);
OFFSET(PEB, BeingDebugged, 0x02);
OFFSET(PEB, Ldr, 0x0c);
OFFSET(PEB, ProcessParameters, 0x10);
OFFSET(PEB, PostProcessInitRoutine, 0x14c);
OFFSET(PEB, SessionId, 0x1d4);
OFFSET(PEB_LDR_DATA, InMemoryOrderModuleList, 0x14);
OFFSET(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks, 0x08);
OFFSET(LDR_DATA_TABLE_ENTRY, DllBase, 0x18);
OFFSET(LDR_DATA_TABLE_ENTRY, FullDllName, 0x24);
OFFSET(LDR_DATA_TABLE_ENTRY, TimeDateStamp, 0x44);
OFFSET(RTL_USER_PROCESS_PARAMETERS, ImagePathName, 0x38);
OFFSET(RTL_USER_PROCESS_PARAMETERS, CommandLine, 0x40);

#elif defined(__x86_64__) || defined(__aarch64__)
SIZE(UNICODE_STRING, 0x10);
SIZE(LIST_ENTRY, 0x10);
OFFSET(NT_TIB, ExceptionList, 0x00);
OFFSET(NT_TIB, StackBase, 0x08);
OFFSET(NT_TIB, StackLimit, 0x10);
OFFSET(NT_TIB, FiberData, 0x20);
OFFSET(NT_TIB, Self, 0x30);
OFFSET(TEB, ProcessEnvironmentBlock, 0x60);
OFFSET(TEB, TlsSlots, 0x1480);
OFFSET(TEB, ReservedForOle, 0x1758);
OFFSET(TEB, TlsExpansionSlots, 0x1780);
OFFSET(PEB, BeingDebugged, 0x02);
OFFSET(PEB, Ldr, 0x18);
OFFSET(PEB, ProcessParameters, 0x20);
OFFSET(PEB, PostProcessInitRoutine, 0x230);
OFFSET(PEB, SessionId, 0x2c0);
OFFSET(PEB_LDR_DATA, InMemoryOrderModuleList, 0x20);
OFFSET(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks, 0x10);
OFFSET(LDR_DATA_TABLE_ENTRY, DllBase, 0x30);
OFFSET(LDR_DATA_TABLE_ENTRY, FullDllName, 0x48);
OFFSET(LDR_DATA_TABLE_ENTRY, TimeDateStamp, 0x80);
OFFSET(RTL_USER_PROCESS_PARAMETERS, ImagePathName, 0x60);
OFFSET(RTL_USER_PROCESS_PARAMETERS, CommandLine, 0x70);

#if defined(__x86_64__)
SIZE(CONTEXT, 0x4d0);
SIZE(XMM_SAVE_AREA32, 0x200);
OFFSET(CONTEXT, ContextFlags, 0x30);
OFFSET(CONTEXT, MxCsr, 0x34);
OFFSET(CONTEXT, SegCs, 0x38);
OFFSET(CONTEXT, SegDs, 0x3a);
OFFSET(CONTEXT, SegEs, 0x3c);
OFFSET(CONTEXT, SegFs, 0x3e);
OFFSET(CONTEXT, SegGs, 0x40);
OFFSET(CONTEXT, SegSs, 0x42);
OFFSET(CONTEXT, EFlags, 0x44);
OFFSET(CONTEXT, Rax, 0x78);
OFFSET(CONTEXT, Rcx, 0x80);
OFFSET(CONTEXT, Rdx, 0x88);
OFFSET(CONTEXT, Rbx, 0x90);
OFFSET(CONTEXT, Rsp, 0x98);
OFFSET(CONTEXT, Rbp, 0xa0);
OFFSET(CONTEXT, Rsi, 0xa8);
OFFSET(CONTEXT, Rdi, 0xb0);
OFFSET(CONTEXT, R8, 0xb8);
OFFSET(CONTEXT, R9, 0xc0);
OFFSET(CONTEXT, R10, 0xc8);
OFFSET(CONTEXT, R11, 0xd0);
OFFSET(CONTEXT, R12, 0xd8);
OFFSET(CONTEXT, R13, 0xe0);
OFFSET(CONTEXT, R14, 0xe8);
OFFSET(CONTEXT, R15, 0xf0);
OFFSET(CONTEXT, Rip, 0xf8);
OFFSET(CONTEXT, FltSave, 0x100);
OFFSET(CONTEXT, Xmm0, 0x1a0);
OFFSET(CONTEXT, Xmm15, 0x290);
#else
SIZE(CONTEXT, 0x390);
OFFSET(CONTEXT, ContextFlags, 0x00);
OFFSET(CONTEXT, Cpsr, 0x04);
OFFSET(CONTEXT, X0, 0x08);
OFFSET(CONTEXT, X28, 0xe8);
OFFSET(CONTEXT, Fp, 0xf0);
OFFSET(CONTEXT, Lr, 0xf8);
OFFSET(CONTEXT, Sp, 0x100);
OFFSET(CONTEXT, Pc, 0x108);
OFFSET(CONTEXT, V, 0x110);
OFFSET(CONTEXT, Fpcr, 0x310);
OFFSET(CONTEXT, Fpsr, 0x314);
#endif

#else
#error Unsupported guest architecture for public Windows layout probes
#endif
