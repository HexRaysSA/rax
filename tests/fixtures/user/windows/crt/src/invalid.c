#include "common.h"
static volatile DWORD global_calls, local_calls;
static DWORD parent_tid, worker_tid;
static BOOL explicit_noinfo;
static BOOL provided_arguments;
static const WORD expression_text[] = {0x45, 0x20ac, 0};
static const WORD function_text[] = {0x46, 0};
static const WORD file_text[] = {0x50, 0};
#define RESERVED_COOKIE ((UPTR)(sizeof(UPTR) == 4 ? 0x76543210u : 0x1234567876543210ull))
typedef void (CRTCALL *InvalidProc)(const WORD *, const WORD *, const WORD *, unsigned int, UPTR);
static void CRTCALL global_handler(const WORD *expression, const WORD *function,
                                  const WORD *file, unsigned int line, UPTR reserved) {
    void *p;
    check(GetCurrentThreadId() == parent_tid, 150);
    if (explicit_noinfo) check(!expression && !function && !file && line == 0 && reserved == 0, 151);
    if (provided_arguments) {
        check(expression == expression_text && function == function_text && file == file_text, 148);
        check(line == 0x89abcdefu && reserved == RESERVED_COOKIE, 149);
    }
    ++global_calls;
    /* Returning/reentering handlers are guest code, not a host stub. */
    p = malloc(17); check(p != 0, 152); free(p);
    *_errno() = 777;
}
static void CRTCALL local_handler(const WORD *expression, const WORD *function,
                                 const WORD *file, unsigned int line, UPTR reserved) {
    check(GetCurrentThreadId() == worker_tid, 153);
    if (explicit_noinfo) check(!expression && !function && !file && line == 0 && reserved == 0, 154);
    ++local_calls; *_errno() = 888;
}
static DWORD WINAPI worker(void *unused) {
    (void)unused;
    worker_tid = GetCurrentThreadId();
    check(_get_invalid_parameter_handler() == global_handler, 155);
    check(_get_thread_local_invalid_parameter_handler() == 0, 156);
    check(_set_thread_local_invalid_parameter_handler(local_handler) == 0, 157);
    check(_get_thread_local_invalid_parameter_handler() == local_handler, 158);
    check(_get_errno(0) == EINVAL && *_errno() == EINVAL && local_calls == 1, 159);
    explicit_noinfo = 1; _invalid_parameter_noinfo(); explicit_noinfo = 0;
    check(local_calls == 2 && global_calls == 5 && *_errno() == 888, 160);
    check(_set_thread_local_invalid_parameter_handler(0) == local_handler, 161);
    check(_get_thread_local_invalid_parameter_handler() == 0, 162);
    return 0;
}
void entry(void) {
    HANDLE thread;
    parent_tid = GetCurrentThreadId();
    check(_get_invalid_parameter_handler() == 0 && _get_thread_local_invalid_parameter_handler() == 0, 163);
    check(_set_invalid_parameter_handler(global_handler) == 0, 164);
    check(_get_invalid_parameter_handler() == global_handler, 165);
    check(_get_errno(0) == EINVAL && *_errno() == EINVAL && global_calls == 1, 166);
    check(_get_doserrno(0) == EINVAL && *_errno() == EINVAL && global_calls == 2, 167);
    check(_msize(0) == FULL_SIZE && *_errno() == EINVAL && global_calls == 3, 168);
    explicit_noinfo = 1; _invalid_parameter_noinfo(); explicit_noinfo = 0;
    check(global_calls == 4 && *_errno() == 777, 169);
    {
        HANDLE module;
        InvalidProc invoke;
#ifdef APISET_CRT
        module = LoadLibraryA("api-ms-win-crt-runtime-l1-1-0.dll");
#else
        module = LoadLibraryA("ucrtbase.dll");
#endif
        check(module != 0, 176);
        /* Documented named personality entry; native export availability is unknown. */
        invoke = (InvalidProc)GetProcAddress(module, "_invalid_parameter");
        check(invoke != 0, 177);
        provided_arguments = 1;
        invoke(expression_text, function_text, file_text, 0x89abcdefu, RESERVED_COOKIE);
        provided_arguments = 0;
        check(global_calls == 5 && *_errno() == 777, 178);
        check(FreeLibrary(module), 179);
    }
    thread = CreateThread(0, 0, worker, 0, 0, 0); check(thread != 0, 170);
    wait(thread); close(thread);
    check(local_calls == 2 && global_calls == 5 && *_errno() == 777, 171);
    check(_set_invalid_parameter_handler(0) == global_handler, 172);
    check(_get_invalid_parameter_handler() == 0, 173);
    ExitProcess(0);
}
