#include "common.h"
/* Assembly helpers deliberately form a private agreement for FP control edits. */
extern DWORD ProbeSwitch(void *, UPTR);
extern DWORD FpRead(void);
extern void FpWrite(DWORD);
extern DWORD X87Read(void);
extern void X87Write(DWORD);
static void *root, *other;
static DWORD fp_original, x87_original, flags, step;
static DWORD fp_first, fp_second, fp_third;
static DWORD x87_first, x87_second, x87_third;
static int fp_matches(DWORD expected) {
#if defined(_M_ARM64)
    return ((FpRead() ^ expected) & 0x01c00000u) == 0; /* FPCR FZ/RMode. */
#elif defined(_M_X64)
    return ((FpRead() ^ expected) & 0xffc0u) == 0; /* Nonvolatile MXCSR controls. */
#else
    return FpRead() == expected; /* x86 explicit FLOAT_SWITCH state agreement. */
#endif
}
static void WINAPI body(void *arg) {
    volatile UPTR canary = COOKIE;
    check(arg == (void *)(COOKIE + 7) && fiber_data() == arg, 131);
    stack_check(132);
    FpWrite(fp_second); X87Write(x87_second);
    step = 1;
    check(ProbeSwitch(root, COOKIE + 0x22) == 0, 134);
    check(canary == COOKIE && step == 1, 135);
#if defined(_M_IX86)
    check(fp_matches(flags ? fp_second : fp_third), 136);
    check(X87Read() == (flags ? x87_second : x87_third), 137);
#else
    check(fp_matches(fp_second), 138);
#if defined(_M_X64)
    check(X87Read() == x87_second, 149);
#endif
#endif
    step = 2;
    SwitchToFiber(root);
    ExitProcess(139);
}
static void round(DWORD use_flags) {
    flags = use_flags; step = 0;
    root = ConvertThreadToFiberEx((void *)(COOKIE + 6), flags);
    check(root && current_fiber() == root, 140);
    other = CreateFiberEx(4096, 65536, flags, body, (void *)(COOKIE + 7));
    check(other != 0, 141);
    FpWrite(fp_first); X87Write(x87_first);
    check(ProbeSwitch(other, COOKIE + 0x11) == 0 && step == 1, 142);
#if defined(_M_IX86)
    check(fp_matches(flags ? fp_first : fp_second), 143);
    check(X87Read() == (flags ? x87_first : x87_second), 144);
#else
    check(fp_matches(fp_first), 145);
#if defined(_M_X64)
    check(X87Read() == x87_first, 150);
#endif
#endif
    FpWrite(fp_third); X87Write(x87_third);
    check(ProbeSwitch(other, COOKIE + 0x33) == 0 && step == 2, 146);
    DeleteFiber(other);
    check(ConvertFiberToThread(), 147);
    FpWrite(fp_original); X87Write(x87_original);
}
void entry(void) {
    fp_original = FpRead(); x87_original = X87Read();
#if defined(_M_ARM64)
    /* FPCR.RMode[23:22] is nonvolatile in the Windows ARM64 ABI. */
    fp_first = (fp_original & ~0x00c00000u) | 0x00400000u;
    fp_second = (fp_original & ~0x00c00000u) | 0x00800000u;
    fp_third = (fp_original & ~0x00c00000u) | 0x00c00000u;
#else
    /* MXCSR.RC[14:13]; all exception masks stay at their original values. */
    fp_first = (fp_original & ~0x6000u) | 0x2000u;
    fp_second = (fp_original & ~0x6000u) | 0x4000u;
    fp_third = (fp_original & ~0x6000u) | 0x6000u;
#endif
    x87_first = (x87_original & ~0x0c00u) | 0x0400u;
    x87_second = (x87_original & ~0x0c00u) | 0x0800u;
    x87_third = (x87_original & ~0x0c00u) | 0x0c00u;
    round(FLOAT_SWITCH);
    round(0);
    check(FpRead() == fp_original && X87Read() == x87_original, 148);
    ExitProcess(0);
}
