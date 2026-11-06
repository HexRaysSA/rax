/* Owned-process installed-library witness. No CRT or external target. */
typedef unsigned long DWORD;
typedef __UINTPTR_TYPE__ UPTR;
typedef void *HANDLE;
#define API __declspec(dllimport)
#define CALL __stdcall
API DWORD CALL GetCurrentThreadId(void);
API HANDLE CALL CreateThread(void *, UPTR, DWORD(CALL *)(void *), void *, DWORD, DWORD *);
API DWORD CALL ResumeThread(HANDLE);
API DWORD CALL WaitForSingleObject(HANDLE, DWORD);
API int CALL GetExitCodeThread(HANDLE, DWORD *);
API int CALL CloseHandle(HANDLE);
API __declspec(noreturn) void CALL ExitProcess(DWORD);

static volatile DWORD creator, observed, state;

static DWORD CALL worker(void *argument) {
    observed = GetCurrentThreadId();
    if ((UPTR)argument != 0x123456u || observed == 0 || observed == creator)
        return 90;
    state = 0xcafebeefu;
    return 0x37;
}

void entry(void) {
    DWORD id = 0, code = 0;
    creator = GetCurrentThreadId();
    HANDLE thread = CreateThread(0, 65536, worker, (void *)(UPTR)0x123456u, 4, &id);
    if (!thread || !id || id == creator) ExitProcess(11);
    if (state || observed) ExitProcess(12);
    if (!GetExitCodeThread(thread, &code) || code != 259) ExitProcess(13);
    if (ResumeThread(thread) != 1) ExitProcess(14);
    if (WaitForSingleObject(thread, 0xffffffffu) != 0) ExitProcess(15);
    if (state != 0xcafebeefu || observed != id) ExitProcess(16);
    if (!GetExitCodeThread(thread, &code) || code != 0x37) ExitProcess(17);
    if (!CloseHandle(thread)) ExitProcess(18);
    ExitProcess(0);
}
