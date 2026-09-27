#include "common.h"
static volatile DWORD detach_count, tls_count, invalid_count, signal_count;
static void *output_handle;
static FILE *output_stream;
static char output_buffer[64];
static DWORD mode;
static const DWORD CPP_EXCEPTION = 0xe06d7363u;
static const DWORD OTHER_EXCEPTION = 0x12345678u;
typedef int (CRTCALL *CONFIGURE)(volatile DWORD *);

static void prepare(void) {
    output_handle = CreateFileW(L"pending.bin", 0xc0000000u, 3, 0, 2, 0x80, 0);
    check(output_handle != (void *)(IPTR)-1, 101);
    int fd = _open_osfhandle((IPTR)output_handle, 0x8002); /* O_BINARY | O_RDWR */
    check(fd >= 0, 102);
    output_stream = _wfdopen(fd, L"wb");
    check(output_stream != 0, 103);
    check(setvbuf(output_stream, output_buffer, 0, sizeof(output_buffer)) == 0, 104);
    check(fwrite("B", 1, 1, output_stream) == 1, 105);
    long long bytes = -1;
    check(GetFileSizeEx(output_handle, &bytes) && bytes == 0, 106);
    void *dll = LoadLibraryW(L"companion.dll");
    check(dll != 0, 107);
    CONFIGURE configure = (CONFIGURE)GetProcAddress(dll, "configure");
    check(configure && configure(&detach_count) == 1, 108);
}

static void WINAPI tls_callback(void *module, DWORD reason, void *reserved) {
    check(module == 0 && reason == 0 && reserved == 0, 109);
    ++tls_count;
    tag('T');
}
static void CRTCALL ordinary_a(void) { tag('A'); }
static void CRTCALL ordinary_c(void) { tag('C'); }
static void CRTCALL ordinary_b(void) {
    tag('B');
    check(_crt_atexit(ordinary_c) == 0, 110);
}
static void CRTCALL quick_q(void) { tag('Q'); }
static void CRTCALL quick_s(void) { tag('S'); }
static void CRTCALL quick_r(void) {
    tag('R');
    check(_crt_at_quick_exit(quick_s) == 0, 111);
}
static void queues(void) {
    _register_thread_local_exe_atexit_callback(tls_callback);
    check(_crt_atexit(ordinary_a) == 0 && _crt_atexit(ordinary_b) == 0, 112);
    check(_crt_at_quick_exit(quick_q) == 0 && _crt_at_quick_exit(quick_r) == 0, 113);
}
static void CRTCALL handler_stop(void) { tag('H'); forced(mode == 8 ? 23 : 24); }
static void CRTCALL handler_return(void) { tag('H'); }
static void CRTCALL handler_fault(void) { tag('H'); RaiseException(OTHER_EXCEPTION, 0, 0, 0); tag('F'); }
static void CRTCALL raise_other(void) { RaiseException(OTHER_EXCEPTION, 0, 0, 0); }
static void CRTCALL raise_cpp(void) { RaiseException(CPP_EXCEPTION, 0, 0, 0); }
static void CRTCALL handler_inner(void) { tag('H'); inner_call(raise_other); tag('R'); }
static void CRTCALL escaped(void) { tag('X'); RaiseException(mode == 16 ? CPP_EXCEPTION : OTHER_EXCEPTION, 0, 0, 0); tag('F'); }
static void CRTCALL escaped_inner(void) { tag('X'); inner_call(raise_cpp); tag('R'); }
static void CRTCALL escaped_unwind(void) { tag('X'); unwind_call(raise_cpp); tag('F'); }
int CRTCALL outer_handler(void *record, void *frame, void *context, void *dispatcher) {
    (void)record; (void)frame; (void)context; (void)dispatcher;
    tag('O');
    forced(25);
}
int CRTCALL inner_handler(void *record, void *frame, void *context, void *dispatcher) {
    (void)frame; (void)context; (void)dispatcher;
    const DWORD code = *(const DWORD *)record;
    check(code == (mode == 19 ? CPP_EXCEPTION : OTHER_EXCEPTION), 114);
    tag('I');
    return 0; /* ExceptionContinueExecution; continuable RaiseException. */
}
int CRTCALL unwind_handler(void *record, void *frame, void *context, void *dispatcher) {
    (void)frame; (void)context; (void)dispatcher;
    const DWORD *fields = record;
    check(fields[0] == CPP_EXCEPTION, 153);
    if (fields[1] & 2) tag('U'); /* EXCEPTION_UNWINDING, not first-pass search. */
    return 1; /* ExceptionContinueSearch. */
}
static void CRTCALL abort_handler(int number) {
    check(number == 22 && signal(22, (SIGNAL)(UPTR)2) == (SIGNAL)0, 115);
    tag('S');
    check(_set_abort_behavior(0, 2) == 2, 116);
}
static void CRTCALL signal_b(int number) {
    check(number == 22 && signal(6, (SIGNAL)(UPTR)2) == (SIGNAL)0, 117);
    ++signal_count;
    tag('B');
}
static void CRTCALL signal_a(int number) {
    check(number == 6 && signal(22, (SIGNAL)(UPTR)2) == (SIGNAL)0, 118);
    ++signal_count;
    tag('A');
    check(signal(6, signal_b) == (SIGNAL)0, 119);
}
static void CRTCALL signal_z(int number) { check(number == 15, 120); ++signal_count; tag('Z'); }
static void CRTCALL invalid_handler(const WCHAR *expression, const WCHAR *function,
                                  const WCHAR *file, unsigned int line, UPTR reserved) {
    check(!expression && !function && !file && !line && !reserved, 121);
    ++invalid_count;
    tag('I');
}
static void signal_roundtrip(void) {
    check(signal(22, signal_a) == (SIGNAL)0, 122);
    check(signal(6, (SIGNAL)(UPTR)2) == signal_a, 123);
    check(raise(6) == 0 && raise(22) == 0 && signal_count == 2, 124);
    check(signal(22, (SIGNAL)(UPTR)1) == (SIGNAL)0 && raise(6) == 0, 125);
    check(signal(6, (SIGNAL)(UPTR)2) == (SIGNAL)(UPTR)1, 126);
    check(signal(15, signal_z) == (SIGNAL)0 && raise(15) == 0 && signal_count == 3, 127);
    check(signal(15, (SIGNAL)(UPTR)2) == (SIGNAL)0, 128);
    *_errno() = 91;
    check(signal(1, (SIGNAL)0) == (SIGNAL)(IPTR)-1 && *_errno() == 91, 129);
    check(signal(23, (SIGNAL)0) == (SIGNAL)(IPTR)-1 && *_errno() == 22, 130);
    check(_set_invalid_parameter_handler(invalid_handler) == (INVALID)0, 131);
    check(raise(23) == -1 && invalid_count == 1 && *_errno() == 22, 132);
    tag('V');
}
static void CRTCALL execute(void) {
    switch (mode) {
    case 0: queues(); exit(17);
    case 1: queues(); quick_exit(18);
    case 2: queues(); _exit(19);
    case 3: queues(); _Exit(20);
    case 4: ExitProcess(21);
    case 5: forced(22);
    case 6: {
        queues(); _cexit();
        check(tls_count == 1 && detach_count == 0, 133);
        long long bytes = -1;
        check(GetFileSizeEx(output_handle, &bytes) && bytes == 0, 134);
        _cexit();
        check(tls_count == 2 && detach_count == 0, 135);
        tag('V'); ExitProcess(0);
    }
    case 7: queues(); _c_exit(); check(!tls_count && !detach_count, 136); tag('V'); ExitProcess(0);
    case 8: check(set_terminate(handler_stop) != 0 && _get_terminate() == handler_stop, 137);
            _register_thread_local_exe_atexit_callback(tls_callback);
            _register_thread_local_exe_atexit_callback(tls_callback); break;
    case 9: _register_thread_local_exe_atexit_callback(tls_callback);
            _register_thread_local_exe_atexit_callback(tls_callback); break;
    case 10: check(set_terminate(handler_return) != 0, 138); _set_abort_behavior(0, 2); terminate();
    case 11: check(set_terminate(handler_fault) != 0, 139); _set_abort_behavior(0, 2); terminate();
    case 12: check(signal(22, abort_handler) == (SIGNAL)0, 140); abort();
    case 13: check(signal(22, (SIGNAL)(UPTR)1) == (SIGNAL)0, 141); _set_abort_behavior(0, 2); abort();
    case 14: signal_roundtrip(); ExitProcess(0);
    case 15: check(signal(15, (SIGNAL)(UPTR)2) == (SIGNAL)0, 142); raise(15); break;
    case 16: case 17:
        check(set_terminate(handler_stop) != 0, 143);
        _register_thread_local_exe_atexit_callback(tls_callback);
        check(_crt_atexit(escaped) == 0, 144); exit(27);
    case 18: check(set_terminate(handler_inner) != 0, 145); _set_abort_behavior(0, 2); terminate();
    case 19: check(set_terminate(handler_stop) != 0, 146);
        _register_thread_local_exe_atexit_callback(tls_callback);
        check(_crt_atexit(ordinary_a) == 0 && _crt_atexit(escaped_inner) == 0, 147); exit(26);
    case 20: check(set_terminate(handler_stop) != 0, 154);
        _register_thread_local_exe_atexit_callback(tls_callback);
        check(_crt_atexit(escaped_unwind) == 0, 155); exit(28);
    }
    forced(148); /* Every nominally nonreturning path must not fall through. */
}
void entry(void) {
    const WCHAR *line = GetCommandLineW(), *last = line;
    for (const WCHAR *p = line; *p; ++p) if (*p == ' ' || *p == '\t') last = p + 1;
    check(*last >= '0' && *last <= '9', 149);
    mode = 0;
    while (*last >= '0' && *last <= '9') mode = mode * 10 + *last++ - '0';
    check(*last == 0 && mode < 21, 150);
    prepare();
    outer_call(execute);
    forced(151);
}
