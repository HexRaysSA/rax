#define main preliminary_lifetime_main
#include "probe-lifetime-v1.c"
#undef main

static volatile LONG apc_count;
static VOID NTAPI completed(PVOID context, PIO_STATUS_BLOCK io, ULONG reserved) {
    (void)context; (void)io; (void)reserved;
    InterlockedIncrement(&apc_count);
}

static void observation(unsigned group, unsigned index, ULONG filter, unsigned event_kind,
                        unsigned key_kind, unsigned memory_kind, unsigned buffer_kind,
                        unsigned apc) {
    HANDLE key = NULL, restricted = NULL;
    if (open(&key) != 0) ExitProcess(20);
    HANDLE event = CreateEventW(NULL, TRUE, TRUE, NULL);
    HANDLE event_restricted = NULL;
    if (!event) ExitProcess(21);
    if (key_kind == 4 || key_kind == 5) {
        if (!DuplicateHandle(GetCurrentProcess(), key, GetCurrentProcess(), &restricted,
                             key_kind == 4 ? KEY_QUERY_VALUE : KEY_NOTIFY, FALSE, 0)) ExitProcess(22);
    }
    if (event_kind == 4 || event_kind == 5) {
        if (!DuplicateHandle(GetCurrentProcess(), event, GetCurrentProcess(), &event_restricted,
                             event_kind == 4 ? EVENT_MODIFY_STATE : SYNCHRONIZE, FALSE, 0)) ExitProcess(23);
    }
    unsigned char *storage = VirtualAlloc(NULL, 8192, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!storage) ExitProcess(24);
    memset(storage, 0xcc, 8192);
    NativeIosb *io = (NativeIosb *)storage;
    if (memory_kind >= 8 && memory_kind < 16) io = (NativeIosb *)(storage + memory_kind - 8);
    if (memory_kind == 1) io = NULL;
    if (memory_kind == 2) io = (NativeIosb *)(storage + 1);
    if (memory_kind == 5) io = (NativeIosb *)(storage + 4096 - sizeof(void *));
    if (memory_kind == 7) io = (NativeIosb *)(uintptr_t)0x123;
    DWORD old;
    if (memory_kind == 3 && !VirtualProtect(storage, 4096, PAGE_READONLY, &old)) ExitProcess(25);
    if (memory_kind == 4 && !VirtualProtect(storage, 4096, PAGE_NOACCESS, &old)) ExitProcess(26);
    if (memory_kind == 5 && !VirtualProtect(storage + 4096, 4096, PAGE_NOACCESS, &old)) ExitProcess(27);
    if (memory_kind == 6 && !VirtualProtect(storage, 4096, PAGE_READWRITE | PAGE_GUARD, &old)) ExitProcess(28);
    HANDLE key_arg = key_kind == 1 ? NULL : key_kind == 2 ? (HANDLE)(uintptr_t)0x12345678 :
                     key_kind == 3 ? event : restricted ? restricted : key;
    HANDLE event_arg = event_kind == 0 ? NULL : event_kind == 2 ? (HANDLE)(uintptr_t)0x12345678 :
                       event_kind == 3 ? key : event_restricted ? event_restricted : event;
    PVOID buffer = buffer_kind == 1 ? storage + 6000 : buffer_kind == 2 ? (void *)(uintptr_t)1 : NULL;
    ULONG length = buffer_kind == 3 ? 0xffffffff : buffer_kind == 0 ? 0 : 1;
    PVOID routine = NULL;
    if (apc) {
        PIO_APC_ROUTINE function = completed;
        memcpy(&routine, &function, sizeof routine);
    }
    LONG status = notify_key(key_arg, event_arg, routine, NULL, io, filter, FALSE, buffer, length, TRUE);
    if (!VirtualProtect(storage, 8192, PAGE_READWRITE, &old)) ExitProcess(29);
    unsigned char armed[2 * sizeof(void *)], final[2 * sizeof(void *)];
    memcpy(armed, storage, sizeof armed);
    DWORD event_armed = WaitForSingleObject(event, 0);
    if (restricted && close_handle(restricted) != 0) ExitProcess(30);
    if (close_handle(key) != 0) ExitProcess(31);
    DWORD event_final = WaitForSingleObject(event, event_arg && status == 0x103 ? 100 : 0);
    memcpy(final, storage, sizeof final);
    printf("%s{\"group\":%u,\"index\":%u,\"filter\":%lu,\"event_kind\":%u,"
           "\"key_kind\":%u,\"memory_kind\":%u,\"buffer_kind\":%u,\"apc\":%u,"
           "\"status\":%lu,\"event_armed\":%lu,\"event_final\":%lu,\"iosb_armed\":\"",
           group == 0 && index == 0 ? "" : ",", group, index, filter, event_kind,
           key_kind, memory_kind, buffer_kind, apc, (ULONG)status, event_armed, event_final);
    hex(armed, sizeof armed); printf("\",\"iosb_final\":\"");
    hex(final, sizeof final); printf("\"}");
    if (event_restricted && !CloseHandle(event_restricted)) ExitProcess(32);
    if (!CloseHandle(event)) ExitProcess(33);
}

int main(void) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    LOAD(open_key, "NtOpenKeyEx"); LOAD(notify_key, "NtNotifyChangeKey");
    LOAD(wait_one, "NtWaitForSingleObject"); LOAD(close_handle, "NtClose");
    DWORD before = 0, after = 0;
    if (!GetProcessHandleCount(GetCurrentProcess(), &before)) return 2;
    printf("{\"pointer_bytes\":%zu,\"handles_before\":%lu,\"rows\":[", sizeof(void *), before);
    unsigned index = 0;
    for (unsigned bit = 0; bit < 32; ++bit)
    for (unsigned inverse = 0; inverse < 2; ++inverse)
    for (unsigned event = 0; event < 2; ++event) {
        ULONG filter = (ULONG)1 << bit;
        if (inverse) filter = ~filter;
        observation(0, index++, filter, event, 0, 0, 0, 0);
    }
    index = 0;
    for (unsigned memory = 8; memory < 16; ++memory)
    for (unsigned event = 0; event < 2; ++event)
        observation(1, index++, 1, event, 0, memory, 0, 0);
    index = 0;
    for (unsigned memory = 0; memory < 8; ++memory)
    for (unsigned filter = 0; filter < 4; ++filter)
    for (unsigned key = 0; key < 2; ++key)
        observation(2, index++, filter == 0 ? 1 : filter == 1 ? 16 : filter == 2 ? 0x10000001 : 0xffffffff,
                    2, key, memory, 0, 0);
    if (!GetProcessHandleCount(GetCurrentProcess(), &after)) return 9;
    printf("],\"handles_after\":%lu,\"apc_count\":%ld}\n", after, apc_count);
    return before == after ? 0 : 10;
}
