#include <windows.h>
#include <winternl.h>
#include <initializer_list>

using AlertId = LONG(NTAPI *)(HANDLE);
using WaitId = LONG(NTAPI *)(void *, LARGE_INTEGER *);
using AlertHandle = LONG(NTAPI *)(HANDLE);
using TestAlert = LONG(NTAPI *)();
static AlertId alert_id;
static WaitId wait_id;
static AlertHandle alert_handle;
static TestAlert test_alert;
static HANDLE output, stop_event;
static unsigned char *pages;
static char line[4096];
static unsigned position, case_index;
static volatile LONG ready;
static DWORD worker_tid;
static ULONG worker_waits[8];

static void text(const char *s) { while (*s) line[position++] = *s++; }
static void field(ULONGLONG value) {
    const char digits[] = "0123456789abcdef";
    line[position++] = ' ';
    for (unsigned n = 16; n; --n) line[position++] = digits[(value >> ((n - 1) * 4)) & 15];
}
static void flush() {
    line[position++] = '\n';
    DWORD written;
    if (!WriteFile(output, line, position, &written, nullptr) || written != position) ExitProcess(2);
    position = 0;
}
static void protect(unsigned char *p, SIZE_T size, DWORD value) {
    DWORD old;
    if (!VirtualProtect(p, size, value, &old)) ExitProcess(3);
}
static DWORD protection(unsigned char *p) {
    MEMORY_BASIC_INFORMATION info;
    if (!VirtualQuery(p, &info, sizeof(info))) ExitProcess(4);
    return info.Protect;
}
static ULONG poll() {
    LARGE_INTEGER zero = {};
    return ULONG(wait_id(nullptr, &zero));
}

using AlertEx = LONG(NTAPI *)(HANDLE, void *);
static AlertEx alert_ex;

using QuerySystem = LONG(NTAPI *)(ULONG, void *, ULONG, ULONG *);
static QuerySystem query_system;
static unsigned char *system_buffer;
static unsigned address_kind;
static void *held_wait_address;
static ULONG worker_result, worker_exception;
static volatile LONG entered, returned;
static ULONG self_found, thread_found;
static DWORD WINAPI blocking_worker(void *) {
    worker_tid=GetCurrentThreadId();
    void *address=held_wait_address;
    LARGE_INTEGER timeout;timeout.QuadPart=-10000000;
    InterlockedExchange(&entered,1);
    __try {worker_result=ULONG(wait_id(address,&timeout));}
    __except(EXCEPTION_EXECUTE_HANDLER){worker_exception=GetExceptionCode();}
    InterlockedExchange(&returned,1);
    return 0x38;
}
static bool state(ULONG &out_state,ULONG &out_reason) {
    self_found=0;thread_found=0;
    ULONG used=0;LONG status=query_system(5,system_buffer,1048576,&used);
    if(status<0||used>1048576)ExitProcess(10);
    ULONG offset=0;
    for(;;) {
        if(offset>used||used-offset<sizeof(SYSTEM_PROCESS_INFORMATION))ExitProcess(11);
        auto info=reinterpret_cast<SYSTEM_PROCESS_INFORMATION *>(system_buffer+offset);
        ULONG span=info->NextEntryOffset?info->NextEntryOffset:used-offset;
        if(ULONG_PTR(info->UniqueProcessId)==GetCurrentProcessId()) {
            self_found=1;
            if(span<sizeof(*info)||info->NumberOfThreads>(span-sizeof(*info))/sizeof(SYSTEM_THREAD_INFORMATION))ExitProcess(12);
            auto threads=reinterpret_cast<SYSTEM_THREAD_INFORMATION *>(info+1);
            for(ULONG i=0;i<info->NumberOfThreads;++i)if(ULONG_PTR(threads[i].ClientId.UniqueThread)==worker_tid) {
                thread_found=1;out_state=threads[i].ThreadState;out_reason=threads[i].WaitReason;return true;
            }
            return false;
        }
        if(!info->NextEntryOffset)return false;
        if(info->NextEntryOffset>used-offset)ExitProcess(13);
        offset+=info->NextEntryOffset;
    }
}

extern "C" __declspec(noreturn) void entry() {
    output=GetStdHandle(STD_OUTPUT_HANDLE);auto ntdll=GetModuleHandleW(L"ntdll.dll");
    alert_ex=reinterpret_cast<AlertEx>(GetProcAddress(ntdll,"NtAlertThreadByThreadIdEx"));
    wait_id=reinterpret_cast<WaitId>(GetProcAddress(ntdll,"NtWaitForAlertByThreadId"));
    query_system=reinterpret_cast<QuerySystem>(GetProcAddress(ntdll,"NtQuerySystemInformation"));
    if(!alert_ex||!wait_id||!query_system)ExitProcess(1);
    system_buffer=static_cast<unsigned char *>(VirtualAlloc(nullptr,1048576,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE));
    if(!system_buffer)ExitProcess(2);
    text("width");field(sizeof(void *));flush();
    for(unsigned shared=0;shared<2;++shared)for(unsigned address=0;address<2;++address)for(unsigned hint=0;hint<3;++hint) {
        SRWLOCK lock,other;InitializeSRWLock(&lock);InitializeSRWLock(&other);
        if(shared)AcquireSRWLockShared(&lock);else AcquireSRWLockExclusive(&lock);
        ULONG_PTR before=ULONG_PTR(lock.Ptr),other_before=ULONG_PTR(other.Ptr);
        held_wait_address=address?static_cast<void *>(&lock):nullptr;
        void *argument=hint==0?nullptr:hint==1?static_cast<void *>(&lock):static_cast<void *>(&other);
        entered=0;returned=0;worker_result=0xfeedface;worker_exception=0;
        HANDLE thread=CreateThread(nullptr,0,blocking_worker,nullptr,0,nullptr);if(!thread)ExitProcess(3);
        while(!InterlockedCompareExchange(&entered,0,0))Sleep(0);
        ULONG st=0,reason=0,queries=0;bool confirmed=false;
        for(;queries<1024;++queries){if(state(st,reason)&&st==5&&!InterlockedCompareExchange(&returned,0,0)){confirmed=true;break;}if(WaitForSingleObject(thread,0)==WAIT_OBJECT_0)break;Sleep(0);}
        if(!confirmed)ExitProcess(14);
        SetLastError(0x76543210);LONG result=LONG(0xfeedface);DWORD exception=0;
        __try {result=alert_ex(reinterpret_cast<HANDLE>(ULONG_PTR(worker_tid)),argument);}
        __except(EXCEPTION_EXECUTE_HANDLER){exception=GetExceptionCode();}
        DWORD error=GetLastError();
        if(WaitForSingleObject(thread,INFINITE)!=WAIT_OBJECT_0)ExitProcess(4);
        DWORD exit;if(!GetExitCodeThread(thread,&exit)||exit!=0x38)ExitProcess(5);
        ULONG_PTR after=ULONG_PTR(lock.Ptr),other_after=ULONG_PTR(other.Ptr);
        text("held");field(shared);field(address);field(hint);field(ULONG(result));field(exception);field(error);field(worker_result);field(worker_exception);field(st);field(reason);field(before);field(after);field(other_before);field(other_after);flush();
        if(!CloseHandle(thread))ExitProcess(6);
        // Only release the lock if the call left the exact acquired native
        // representation intact. Any other result ends the owned process
        // after recording it, without inventing a release protocol.
        if(after!=before||other_after!=other_before)ExitProcess(15);
        if(shared)ReleaseSRWLockShared(&lock);else ReleaseSRWLockExclusive(&lock);
    }
    ExitProcess(0);
}
