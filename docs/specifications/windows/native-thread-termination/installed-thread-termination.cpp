#include <windows.h>

struct Attributes {
    ULONG length;
    HANDLE root;
    void *name;
    ULONG flags;
    void *security;
    void *qos;
};
using Create = LONG(NTAPI *)(HANDLE *, ULONG, Attributes *, HANDLE, void *, void *,
                            ULONG, SIZE_T, SIZE_T, SIZE_T, void *);
using Query = LONG(NTAPI *)(HANDLE, ULONG, void *, ULONG, ULONG *);
struct Basic { LONG status; void *teb; HANDLE pid, tid; ULONG_PTR affinity; LONG priority, base; };
static_assert(sizeof(Basic) == (sizeof(void *) == 8 ? 48 : 28));
extern "C" __declspec(dllexport) volatile LONG rax_thread_object_state[64] = {0x52415854};

static void check(bool condition, LONG stage) {
    if (!condition) {
        rax_thread_object_state[6] = stage;
        rax_thread_object_state[8] = GetLastError();
        ExitProcess(70);
    }
    ++rax_thread_object_state[10];
}
static __declspec(noreturn) void WINAPI worker(void *parameter) {
    InterlockedExchange(&rax_thread_object_state[4], LONG(ULONG_PTR(parameter)));
    ExitThread(0x37);
}
extern "C" __declspec(noreturn) void entry() {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto create = reinterpret_cast<Create>(GetProcAddress(ntdll, "NtCreateThreadEx"));
    auto query = reinterpret_cast<Query>(GetProcAddress(ntdll, "NtQueryInformationThread"));
    check(create && query, 1);
    const ULONG cases[] = {1, 3, 5, 7, 0x21, 0x23, 0x25, 0x27};
    for (unsigned index = 0; index < 8; ++index) {
        ULONG flags = cases[index];
        Attributes attributes = {sizeof(Attributes), nullptr, nullptr, 0x200, nullptr, nullptr};
        HANDLE thread = nullptr;
        DWORD token = 0x12345600 + index;
        rax_thread_object_state[2] = flags;
        InterlockedExchange(&rax_thread_object_state[4], 0);
        LONG status = create(&thread, 0x1fffff, &attributes, GetCurrentProcess(),
                             reinterpret_cast<void *>(worker),
                             reinterpret_cast<void *>(ULONG_PTR(token)), flags, 0, 0, 0, nullptr);
        rax_thread_object_state[3] = status;
        check(status == 0, 10 + index * 16);
        check(thread != nullptr, 11 + index * 16);
        DWORD actual = 0xfeed;
        check(GetHandleInformation(thread, &actual) != FALSE, 12 + index * 16);
        check(actual == 0, 13 + index * 16);
        Basic basic = {}; ULONG length = 0;
        check(query(thread, 0, &basic, sizeof(basic), &length) == 0 && length == sizeof(basic), 140 + index * 16);
        auto teb = static_cast<unsigned char *>(basic.teb);
        USHORT bits = *reinterpret_cast<USHORT *>(teb + (sizeof(void *) == 8 ? 0x17ee : 0xfca));
        check((bits & 0x4008) == ((flags & 2 ? 8 : 0) | (flags & 0x20 ? 0x4000 : 0)), 141 + index * 16);
        unsigned char hidden = 0xcc;
        check(query(thread, 17, &hidden, 1, &length) == 0 && length == 1 && hidden == ((flags & 4) != 0), 142 + index * 16);
        check(TerminateThread(thread, 0x37) != FALSE, 143 + index * 16);
        check(WaitForSingleObject(thread, INFINITE) == WAIT_OBJECT_0, 144 + index * 16);
        DWORD code = 0xfeed;
        check(GetExitCodeThread(thread, &code) != FALSE && code == 0x37, 148 + index * 16);
        check(query(thread, 17, &hidden, 1, &length) == 0 && length == 1 && hidden == ((flags & 4) != 0), 145 + index * 16);
        check(CloseHandle(thread) != FALSE, 146 + index * 16);
        rax_thread_object_state[1] = index + 1;
    }
    ExitProcess(0);
}
