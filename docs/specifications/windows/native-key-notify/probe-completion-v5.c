#define main preliminary_lifetime_main
#include "probe-lifetime-v1.c"
#undef main

int main(void) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    LOAD(open_key, "NtOpenKeyEx"); LOAD(notify_key, "NtNotifyChangeKey");
    LOAD(wait_one, "NtWaitForSingleObject"); LOAD(close_handle, "NtClose");
    DWORD before = 0, after = 0;
    if (!GetProcessHandleCount(GetCurrentProcess(), &before)) return 2;
    printf("{\"pointer_bytes\":%zu,\"handles_before\":%lu,\"rows\":[", sizeof(void *), before);
    unsigned index = 0;
    for (unsigned f = 0; f < 2; ++f)
    for (unsigned protection = 0; protection < 4; ++protection)
    for (unsigned retirement = 0; retirement < 3; ++retirement) {
        HANDLE key = NULL;
        if (open(&key) != 0) return 3;
        HANDLE event = CreateEventW(NULL, TRUE, TRUE, NULL), alias = NULL, replacement = NULL;
        if (!event || !DuplicateHandle(GetCurrentProcess(), event, GetCurrentProcess(), &alias,
                                        0, FALSE, DUPLICATE_SAME_ACCESS)) return 4;
        NativeIosb *io = VirtualAlloc(NULL, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (!io) return 5;
        memset(io, 0xcc, sizeof *io);
        ULONG filter = 1 | (f ? 0x10000000 : 0);
        LONG status = notify_key(key, event, NULL, NULL, io, filter, FALSE, NULL, 0, TRUE);
        unsigned char armed[sizeof *io], final[sizeof *io];
        memcpy(armed, io, sizeof armed);
        uintptr_t event_value = (uintptr_t)event;
        if (retirement) {
            if (!CloseHandle(event)) return 6;
            event = NULL;
            if (retirement == 2) {
                if (!CloseHandle(alias)) return 7;
                alias = NULL;
            }
            replacement = CreateEventW(NULL, TRUE, FALSE, NULL);
            if (!replacement) return 8;
        }
        const DWORD protections[] = {PAGE_READWRITE, PAGE_READONLY, PAGE_NOACCESS, PAGE_READWRITE | PAGE_GUARD};
        DWORD old;
        if (!VirtualProtect(io, 4096, protections[protection], &old)) return 9;
        LONG close_status = (LONG)0xcccccccc;
        ULONG exception = 0;
        __try { close_status = close_handle(key); }
        __except(EXCEPTION_EXECUTE_HANDLER) { exception = GetExceptionCode(); }
        MEMORY_BASIC_INFORMATION query;
        if (VirtualQuery(io, &query, sizeof query) != sizeof query) return 10;
        DWORD observed_protection = query.Protect;
        DWORD original_signal = alias ? WaitForSingleObject(alias, 100) : 0xffffffff;
        DWORD replacement_signal = replacement ? WaitForSingleObject(replacement, 0) : 0xffffffff;
        if (!VirtualProtect(io, 4096, PAGE_READWRITE, &old)) return 11;
        memcpy(final, io, sizeof final);
        printf("%s{\"filter\":%lu,\"protection\":%u,\"retirement\":%u,\"status\":%lu,"
               "\"close_status\":%lu,\"exception\":%lu,\"observed_protection\":%lu,"
               "\"original_signal\":%lu,\"replacement_signal\":%lu,\"handle_reused\":%u,\"iosb_armed\":\"",
               index++ ? "," : "", filter, protection, retirement, (ULONG)status, (ULONG)close_status,
               exception, observed_protection, original_signal, replacement_signal,
               (unsigned)((uintptr_t)replacement == event_value));
        hex(armed, sizeof armed); printf("\",\"iosb_final\":\"");
        hex(final, sizeof final); printf("\"}");
        if (event && !CloseHandle(event)) return 12;
        if (alias && !CloseHandle(alias)) return 13;
        if (replacement && !CloseHandle(replacement)) return 14;
    }
    if (!GetProcessHandleCount(GetCurrentProcess(), &after)) return 15;
    printf("],\"handles_after\":%lu}\n", after);
    return before == after ? 0 : 16;
}
