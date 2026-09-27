#include "common.h"

__declspec(align(16)) static unsigned char poison[544], before[544], after[544], original[544];
static DWORD arithmetic;
extern void CRTCALL fp_snapshot(const void *, void *, void *, void (CRTCALL *)(void), void *, DWORD *);
extern void CRTCALL fp_local_reset(void); /* private instrumentation control, NOT a CRT export */
static volatile DWORD invalid_calls, math_calls;
static int *invalid_errno;
static volatile DWORD nonexecutable = 0x89ABCDEF;
static volatile DWORD worker_kind;

static void put16(unsigned char *p, unsigned int v) { p[0] = v; p[1] = v >> 8; }
static void put32(unsigned char *p, DWORD v) { for (unsigned int i = 0; i < 4; ++i) p[i] = v >> (i * 8); }
static DWORD get32(const unsigned char *p) { DWORD v = 0; for (unsigned int i = 0; i < 4; ++i) v |= (DWORD)p[i] << (i * 8); return v; }
static unsigned int get16(const unsigned char *p) { return p[0] | ((unsigned int)p[1] << 8); }
static void equal(const unsigned char *a, const unsigned char *b, SIZE n, DWORD code) {
    for (SIZE i = 0; i < n; ++i) check(a[i] == b[i], code);
}

static void CRTCALL invalid(const WCHAR *a, const WCHAR *b, const WCHAR *c, unsigned int line, SIZE reserved) {
    check(!a && !b && !c && !line && !reserved, 40);
    check(invalid_errno && *invalid_errno == 22, 47);
    *invalid_errno = 73;
    ++invalid_calls;
}
static int CRTCALL matherr(void *unused) { (void)unused; ++math_calls; return 1; }

static DWORD WINAPI worker(void *unused) {
    (void)unused;
    if (worker_kind == 1) {
        check(_query_app_type() == (int)0x80000000U, 50);
        _set_app_type(0x24681357);
    } else if (worker_kind == 2) {
        check(_configthreadlocale(0) == 2, 51);
        check(_configthreadlocale(1) == 2 && _configthreadlocale(0) == 1, 52);
    } else {
        void **slot = __pxcptinfoptrs();
        check(slot && !*slot, 53);
        *slot = (void *)&nonexecutable;
        check(__pxcptinfoptrs() == slot && *slot == (void *)&nonexecutable, 54);
    }
    return 7;
}
static void thread(DWORD kind) {
    worker_kind = kind;
    void *handle = CreateThread(0, 0, worker, 0, 0, 0);
    DWORD code = 0;
    check(handle && WaitForSingleObject(handle, 0xFFFFFFFFU) == 0, 55);
    check(GetExitCodeThread(handle, &code) && code == 7, 56);
    check(CloseHandle(handle), 57);
}

static void application(void) {
    static const int values[] = {0, 1, 2, -1, 0x7FFFFFFF, (int)0x80000000U};
    check(_query_app_type() == 0, 20);
    SetLastError(0x13579BDF);
    for (SIZE i = 0; i < sizeof(values) / sizeof(values[0]); ++i) {
        _set_app_type(values[i]);
        check(_query_app_type() == values[i], 21);
    }
    check(GetLastError() == 0x13579BDF, 22);
    thread(1);
    check(_query_app_type() == 0x24681357, 23);
    output("app\n", 4);
}

static void locale(int with_thread) {
    SetLastError(0x13579BDF);
    check(_configthreadlocale(0) == 2, 30);
    check(_configthreadlocale(1) == 2 && _configthreadlocale(0) == 1, 31);
    check(_configthreadlocale(-1) == 1 && _configthreadlocale(0) == 1, 32);
    if (with_thread) { thread(2); check(_configthreadlocale(0) == 1, 33); }
    check(_configthreadlocale(2) == 1 && _configthreadlocale(0) == 2, 34);
    check(_configthreadlocale(2) == 2 && _configthreadlocale(0) == 2, 35);
    check(GetLastError() == 0x13579BDF, 36);
    output(with_thread ? "threads\n" : "locale\n", with_thread ? 8 : 7);
}

static void invalid_locale(void) {
    static const int values[] = {3, -2, 0x7FFFFFFF, (int)0x80000000U};
    INVALID old = _set_invalid_parameter_handler(invalid);
    check(!old, 41);
    int *error = _errno();
    check(error != 0, 42);
    invalid_errno = error;
    SetLastError(0x13579BDF);
    for (SIZE i = 0; i < sizeof(values) / sizeof(values[0]); ++i) {
        *error = 91;
        check(_configthreadlocale(values[i]) == -1 && *error == 73, 43);
        check(invalid_calls == i + 1 && _configthreadlocale(0) == 2, 44);
    }
    check(_set_invalid_parameter_handler(0) == invalid, 45);
    check(GetLastError() == 0x13579BDF, 46);
    output("invalid\n", 8);
}

static void user_math(void) {
    SetLastError(0x13579BDF);
    __setusermatherr(matherr);
    check(math_calls == 0, 60);
    __setusermatherr((MATHERR)(void *)&nonexecutable);
    check(math_calls == 0 && nonexecutable == 0x89ABCDEF, 61);
    __setusermatherr(0);
    check(math_calls == 0 && GetLastError() == 0x13579BDF, 62);
    output("math\n", 5);
}

static void floating(int local_control) {
    for (SIZE i = 0; i < sizeof(poison); ++i) poison[i] = 0;
#if defined(_M_ARM64)
    for (SIZE i = 0; i < 512; ++i) poison[i] = (unsigned char)(i * 37 + 0xA5);
    put32(poison + 512, 0x07C00000); /* DN/AHP/FZ + both rounding-mode bits */
    put32(poison + 520, 0x0800009F); /* QC + defined exception-status bits */
    put32(poison + 528, 0xB0000000); /* NZCV independent of FPSR */
#else
    put16(poison, 0x077E);          /* invalid operation unmasked */
    put16(poison + 2, 0xA9E1);     /* TOP=5, pending ES/B and condition bits */
    poison[4] = 0xFF;
    put16(poison + 6, 0x0567);
    put32(poison + 8, 0x11223344);
    put32(poison + 16, 0x55667788);
#if defined(_M_IX86)
    put16(poison + 12, 0x2345); put16(poison + 20, 0x6789);
#else
    put32(poison + 12, 0x12345678); put32(poison + 20, 0x87654321);
#endif
    put32(poison + 24, 0x7FC5);
    for (SIZE i = 0; i < 8; ++i) for (SIZE b = 0; b < 10; ++b)
        poison[32 + i * 16 + b] = (unsigned char)(i * 29 + b * 13 + 7);
    for (SIZE i = 160; i < 416; ++i) poison[i] = (unsigned char)(i * 37 + 0xA5);
#endif
    fp_snapshot(poison, before, after, local_control ? fp_local_reset : _fpreset, original, &arithmetic);
#if defined(_M_IX86)
    check((get16(before) & 0x0F3F) == 0x073E && ((get16(before + 2) >> 11) & 7) == 5, 70);
    /* FLDCW leaves C0/C1/C2/C3 (0x4700) undefined; retain every other FSW bit. */
    check((get16(after) & 0x0F3F) == 0x023F && (get16(after + 2) & 0xB8FF) == 0 && after[4] == 0, 71);
    check(get16(after + 6) == 0 && get32(after + 8) == 0 && get16(after + 12) == 0, 72);
    check(get32(after + 16) == 0 && get16(after + 20) == 0 && get32(after + 24) == 0x1F80, 73);
    /* FXSAVE stores logical ST(i); TOP reset remaps the same physical80 cells. */
    for (SIZE i = 0; i < 8; ++i) equal(after + 32 + i * 16, before + 32 + ((i + 3) & 7) * 16, 10, 74);
    equal(before + 160, after + 160, 8 * 16, 75);
    check(arithmetic == 0x40000000, 76); /* x87 1+1 after nonwaiting FNINIT */
#elif defined(_M_X64)
    equal(before, after, 24, 77); /* x87 environment untouched, including TOP/ES */
    equal(before + 32, after + 32, 8 * 16, 78);
    equal(before + 160, after + 160, 16 * 16, 79);
    check(get32(after + 24) == 0x1F80 && arithmetic == 0x40400000, 80); /* SSE 1.5+1.5 */
#else
    equal(before, after, 512, 81); /* all V0..V31 payloads */
    check(get32(before + 512) == 0x07C00000 && get32(after + 512) == 0, 82);
    check(get32(before + 520) == 0x0800009F && get32(after + 520) == 0, 83);
    equal(before + 528, after + 528, 8, 84);
    check(arithmetic == 0x40000000, 85); /* scalar FP 1+1 after reset */
#endif
    output(local_control ? "fp-control\n" : "fp\n", local_control ? 11 : 3);
}

static void saved_context(void) {
    static unsigned char context[768], expected[768];
    struct { void *record; void *context; } pointers = {0, context};
    static const DWORD flags[] = {0x00010008, 0x00010000, 8, 0, 4};
    void **slot = __pxcptinfoptrs();
    check(slot && !*slot && __pxcptinfoptrs() == slot, 90);
    *slot = &pointers;
    for (SIZE f = 0; f < sizeof(flags) / sizeof(flags[0]); ++f) {
        for (SIZE i = 0; i < sizeof(context); ++i) context[i] = expected[i] = (unsigned char)(i * 17 + 0x53);
        put32(context, flags[f]); put32(expected, flags[f]);
#if defined(_M_IX86)
        if (flags[f] & 0x00010008) { put32(expected + 0x20, 0); put32(expected + 0x24, 0xFFFF); }
#endif
        _fpreset();
        equal(context, expected, sizeof(context), 91);
        check(*slot == &pointers && __pxcptinfoptrs() == slot, 92);
    }
#if !defined(_M_IX86)
    /* Publisher Win64 bodies never consult this PTD cell, even if unusable. */
    *slot = (void *)(SIZE)1;
    _fpreset();
    check(*slot == (void *)(SIZE)1, 97);
#endif
    *slot = 0;
    output("context\n", 8);
}

static void pointer_cell(void) {
    void **slot = __pxcptinfoptrs();
    check(slot && !*slot && __pxcptinfoptrs() == slot, 93);
    *slot = (void *)(SIZE)0x76543210U;
    thread(3);
    check(__pxcptinfoptrs() == slot && *slot == (void *)(SIZE)0x76543210U, 94);
    *slot = 0;
    output("cell\n", 5);
}

void entry(void) {
    switch (mode()) {
        case 0: output("control\n", 8); break;
        case 1: application(); break;
        case 2: locale(0); break;
        case 3: invalid_locale(); break;
        case 4: user_math(); break;
        case 5: floating(0); break;
        case 6: saved_context(); break;
        case 7: locale(1); break;
        case 8: _configthreadlocale(3); ExitProcess(95);
        case 9: pointer_cell(); break;
        case 10: floating(1); break;
        default: ExitProcess(96);
    }
    ExitProcess(0);
}
