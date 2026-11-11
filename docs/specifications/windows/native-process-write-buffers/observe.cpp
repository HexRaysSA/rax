#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>

using NativeFlush = LONG (NTAPI *)();

int main() {
    const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return 1;
    const auto native_flush = reinterpret_cast<NativeFlush>(
        GetProcAddress(ntdll, "NtFlushProcessWriteBuffers"));
    if (!native_flush) return 2;

    USHORT process_machine = 0;
    USHORT native_machine = 0;
    if (!IsWow64Process2(GetCurrentProcess(), &process_machine, &native_machine)) return 3;
    std::printf("ABI pointer=%zu process=%04x native=%04x\n",
                sizeof(void*), unsigned(process_machine), unsigned(native_machine));
    constexpr DWORD sentinel = 0x5a170042;
    for (unsigned i = 0; i != 3; ++i) {
        SetLastError(sentinel);
        const LONG status = native_flush();
        const DWORD native_error = GetLastError();
        SetLastError(sentinel);
        FlushProcessWriteBuffers();
        const DWORD win32_error = GetLastError();
        std::printf("FLUSH index=%u status=%08lx native-last-error=%08lx win32-last-error=%08lx\n",
                    i, static_cast<unsigned long>(status),
                    static_cast<unsigned long>(native_error),
                    static_cast<unsigned long>(win32_error));
        if (status != 0 || native_error != sentinel || win32_error != sentinel) return 4;
    }
    return 0;
}
