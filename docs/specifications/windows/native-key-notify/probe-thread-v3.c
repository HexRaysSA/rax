#define main preliminary_lifetime_main
#include "probe-lifetime-v1.c"
#undef main

typedef LONG (NTAPI *TestAlert)(void);
static TestAlert test_alert;
typedef struct {
    HANDLE key, event, entered, gate;
    NativeIosb io;
    ULONG filter;
    unsigned mode, supplied, use_apc;
    LONG status, alert_status;
    volatile LONG callbacks;
    ULONG callback_status, callback_reserved;
    uintptr_t callback_information;
    int callback_io_matches;
} Work;

static VOID NTAPI callback(PVOID context, PIO_STATUS_BLOCK io, ULONG reserved) {
    Work *work = context;
    work->callback_status = (ULONG)io->Status;
    work->callback_information = io->Information;
    work->callback_reserved = reserved;
    work->callback_io_matches = (void *)io == &work->io;
    InterlockedIncrement(&work->callbacks);
}
static DWORD WINAPI worker(PVOID argument) {
    Work *work = argument;
    PVOID routine = NULL;
    if (work->use_apc) {
        PIO_APC_ROUTINE function = callback;
        memcpy(&routine, &function, sizeof routine);
    }
    SetEvent(work->entered);
    work->status = notify_key(work->key, work->supplied ? work->event : NULL,
                             routine, work, &work->io, work->filter, FALSE,
                             NULL, 0, (BOOLEAN)(work->mode != 2));
    if (work->mode == 1) {
        if (WaitForSingleObject(work->gate, 5000) != WAIT_OBJECT_0) return 99;
        work->alert_status = test_alert();
    }
    return 0;
}
int main(void) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    LOAD(open_key, "NtOpenKeyEx"); LOAD(notify_key, "NtNotifyChangeKey");
    LOAD(wait_one, "NtWaitForSingleObject"); LOAD(close_handle, "NtClose");
    LOAD(test_alert, "NtTestAlert");
    DWORD before = 0, after = 0;
    if (!GetProcessHandleCount(GetCurrentProcess(), &before)) return 2;
    printf("{\"pointer_bytes\":%zu,\"handles_before\":%lu,\"rows\":[", sizeof(void *), before);
    unsigned index = 0;
    for (unsigned f = 0; f < 2; ++f)
    for (unsigned mode = 0; mode < 3; ++mode)
    for (unsigned supplied = 0; supplied < 2; ++supplied)
    for (unsigned apc = 0; apc < 2; ++apc) {
        Work *work = VirtualAlloc(NULL, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (!work || open(&work->key) != 0) return 3;
        work->event = CreateEventW(NULL, TRUE, TRUE, NULL);
        work->entered = CreateEventW(NULL, TRUE, FALSE, NULL);
        work->gate = CreateEventW(NULL, TRUE, FALSE, NULL);
        if (!work->event || !work->entered || !work->gate) return 4;
        work->filter = 1 | (f ? 0x10000000 : 0);
        work->mode = mode; work->supplied = supplied; work->use_apc = apc;
        work->status = work->alert_status = (LONG)0xcccccccc;
        memset(&work->io, 0xcc, sizeof work->io);
        HANDLE thread = CreateThread(NULL, 0, worker, work, 0, NULL);
        if (!thread || WaitForSingleObject(work->entered, 5000) != WAIT_OBJECT_0) return 5;
        DWORD thread_before = WaitForSingleObject(thread, mode == 0 ? 5000 : 25);
        unsigned char prior[sizeof work->io], final[sizeof work->io];
        memcpy(prior, &work->io, sizeof prior);
        DWORD event_before = WaitForSingleObject(work->event, 0);
        LONG closed = close_handle(work->key);
        DWORD event_closed = WaitForSingleObject(work->event, 0);
        if (!SetEvent(work->gate)) return 6;
        DWORD thread_final = WaitForSingleObject(thread, 5000);
        if (thread_final != WAIT_OBJECT_0) return 7;
        DWORD exit_code = 0;
        if (!GetExitCodeThread(thread, &exit_code) || exit_code != 0) return 8;
        DWORD event_final = WaitForSingleObject(work->event, 0);
        memcpy(final, &work->io, sizeof final);
        printf("%s{\"filter\":%lu,\"mode\":%u,\"event_supplied\":%u,\"apc\":%u,"
               "\"status\":%lu,\"thread_before\":%lu,\"event_before\":%lu,"
               "\"close_status\":%lu,\"event_closed\":%lu,\"thread_final\":%lu,"
               "\"event_final\":%lu,\"alert_status\":%lu,\"callbacks\":%ld,"
               "\"callback_status\":%lu,\"callback_information\":%llu,"
               "\"callback_reserved\":%lu,\"callback_io_matches\":%d,\"iosb_before_close\":\"",
               index++ ? "," : "", work->filter, mode, supplied, apc, (ULONG)work->status,
               thread_before, event_before, (ULONG)closed, event_closed, thread_final,
               event_final, (ULONG)work->alert_status, work->callbacks, work->callback_status,
               (unsigned long long)work->callback_information, work->callback_reserved,
               work->callback_io_matches);
        hex(prior, sizeof prior); printf("\",\"iosb_final\":\"");
        hex(final, sizeof final); printf("\"}");
        if (!CloseHandle(thread) || !CloseHandle(work->event) ||
            !CloseHandle(work->entered) || !CloseHandle(work->gate)) return 9;
    }
    if (!GetProcessHandleCount(GetCurrentProcess(), &after)) return 10;
    printf("],\"handles_after\":%lu}\n", after);
    return before == after ? 0 : 11;
}
