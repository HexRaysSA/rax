#include <windows.h>

struct Attributes { ULONG length; HANDLE root; void *name; ULONG flags; void *security; void *qos; };
struct State { volatile LONG dll_attach, dll_detach, tls_attach, tls_detach; };
using Create = LONG(NTAPI *)(HANDLE *, ULONG, Attributes *, HANDLE, void *, void *, ULONG, SIZE_T, SIZE_T, SIZE_T, void *);
using Resume = LONG(NTAPI *)(HANDLE, ULONG *);
using Exit = void(NTAPI *)(ULONG);
static Exit exit_thread;
static DWORD tls_index;
static State *counts;
static volatile LONG vector_seen, block_seen, template_seen;
static HANDLE output;
static char line[1024];
static unsigned position;

static void text(const char *s) { while (*s) line[position++] = *s++; }
static void hex(ULONG_PTR v) {
    const char digits[] = "0123456789abcdef";
    for (unsigned n = sizeof(v) * 2; n; --n) line[position++] = digits[(v >> ((n - 1) * 4)) & 15];
}
static void field(ULONG_PTR v) { text(" "); hex(v); }
static void flush() {
    text("\n"); DWORD written;
    if (!WriteFile(output, line, position, &written, nullptr) || written != position) ExitProcess(3);
    position = 0;
}
static DWORD WINAPI worker(void *) {
    auto teb = reinterpret_cast<unsigned char *>(NtCurrentTeb());
    void **vector = nullptr; SIZE_T read = 0;
    ReadProcessMemory(GetCurrentProcess(), teb + (sizeof(void *) == 8 ? 0x58 : 0x2c), &vector, sizeof(vector), &read);
    InterlockedExchange(&vector_seen, vector != nullptr);
    void *block = nullptr;
    if (vector) ReadProcessMemory(GetCurrentProcess(), vector + tls_index, &block, sizeof(block), &read);
    InterlockedExchange(&block_seen, block != nullptr);
    ULONG sample = 0;
    if (block) ReadProcessMemory(GetCurrentProcess(), block, &sample, sizeof(sample), &read);
    InterlockedExchange(&template_seen, sample == 0x31415926);
    exit_thread(0x37);
    return 0xfeed;
}
extern "C" __declspec(noreturn) void entry() {
    output = GetStdHandle(STD_OUTPUT_HANDLE);
#if defined(_M_ARM64)
    const wchar_t *name = L"flags-arm64.dll";
#elif defined(_M_X64)
    const wchar_t *name = L"flags-x64.dll";
#else
    const wchar_t *name = L"flags-x86.dll";
#endif
    HMODULE dll = LoadLibraryW(name);
    if (!dll) ExitProcess(1);
    auto get_state = reinterpret_cast<State *(*)()>(GetProcAddress(dll, "get_state"));
    auto get_index = reinterpret_cast<DWORD(*)()>(GetProcAddress(dll, "get_index"));
    if (!get_state || !get_index) ExitProcess(2);
    counts = get_state(); tls_index = get_index();
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto create = reinterpret_cast<Create>(GetProcAddress(ntdll, "NtCreateThreadEx"));
    auto resume = reinterpret_cast<Resume>(GetProcAddress(ntdll, "NtResumeThread"));
    exit_thread = reinterpret_cast<Exit>(GetProcAddress(ntdll, "RtlExitUserThread"));
    if (!create || !resume || !exit_thread) ExitProcess(4);
    text("width"); field(sizeof(void *)); field(tls_index); flush();
    ULONG selected = 0; const wchar_t *cmd = GetCommandLineW();
    while (*cmd && *cmd != L' ' ) ++cmd;
    while (*cmd == L' ') ++cmd;
    while (*cmd) { wchar_t c = *cmd++; if (c >= L'0' && c <= L'9') selected = selected * 16 + c - L'0'; else if (c >= L'a' && c <= L'f') selected = selected * 16 + c - L'a'; else break; }
    const ULONG flags[] = {selected};
    for (ULONG f : flags) {
        InterlockedExchange(&counts->dll_attach, 0); InterlockedExchange(&counts->dll_detach, 0);
        InterlockedExchange(&counts->tls_attach, 0); InterlockedExchange(&counts->tls_detach, 0);
        InterlockedExchange(&vector_seen, 0); InterlockedExchange(&block_seen, 0); InterlockedExchange(&template_seen, 0);
        Attributes attributes = {sizeof(Attributes), nullptr, nullptr, 0x200, nullptr, nullptr};
        HANDLE thread = nullptr;
        LONG created = create(&thread, 0x1fffff, &attributes, GetCurrentProcess(),
                              reinterpret_cast<void *>(worker), nullptr, f, 0, 0, 0, nullptr);
        text("case"); field(f); field(ULONG(created)); flush();
        if (created < 0) continue;
        ULONG previous = 0xfeedface;
        LONG resumed = resume(thread, &previous);
        DWORD waited = resumed >= 0 ? WaitForSingleObject(thread, INFINITE) : WAIT_FAILED;
        DWORD code = 0xfeedface;
        BOOL exited = GetExitCodeThread(thread, &code), closed = CloseHandle(thread);
        text("result"); field(f); field(ULONG(resumed)); field(previous); field(waited);
        field(exited); field(code); field(closed);
        field(InterlockedCompareExchange(&counts->dll_attach, 0, 0));
        field(InterlockedCompareExchange(&counts->dll_detach, 0, 0));
        field(InterlockedCompareExchange(&counts->tls_attach, 0, 0));
        field(InterlockedCompareExchange(&counts->tls_detach, 0, 0));
        field(InterlockedCompareExchange(&vector_seen, 0, 0));
        field(InterlockedCompareExchange(&block_seen, 0, 0));
        field(InterlockedCompareExchange(&template_seen, 0, 0)); flush();
        if (resumed < 0 || previous != 1 || waited != WAIT_OBJECT_0 || !exited || code != 0x37 || !closed) ExitProcess(5);
    }
    if (!FreeLibrary(dll)) ExitProcess(6);
    ExitProcess(0);
}
