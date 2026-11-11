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
static ULONG worker_result, worker_exception;
static volatile LONG entered, returned;
static ULONG self_found, thread_found;
static DWORD WINAPI blocking_worker(void *) {
    worker_tid=GetCurrentThreadId();
    void *address=address_kind==0?nullptr:address_kind==1?reinterpret_cast<void *>(ULONG_PTR(1)):pages+128;
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
    pages=static_cast<unsigned char *>(VirtualAlloc(nullptr,12288,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE));
    system_buffer=static_cast<unsigned char *>(VirtualAlloc(nullptr,1048576,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE));
    if(!pages||!system_buffer)ExitProcess(2);
    text("width");field(sizeof(void *));field(sizeof(SYSTEM_PROCESS_INFORMATION));field(sizeof(SYSTEM_THREAD_INFORMATION));flush();
    for(unsigned address=0;address<3;++address)for(unsigned hint=0;hint<8;++hint) {
        protect(pages,12288,PAGE_READWRITE);for(unsigned i=0;i<12288;++i)pages[i]=0;
        void *lock=nullptr;
        switch(hint) {
            case 1:lock=pages+128;break;
            case 2:lock=pages+256;break;
            case 3:lock=reinterpret_cast<void *>(ULONG_PTR(1));break;
            case 4:lock=reinterpret_cast<void *>(~ULONG_PTR(0));break;
            case 5:lock=pages+4096-16;protect(pages,4096,PAGE_READWRITE|PAGE_GUARD);break;
            case 6:lock=pages+4096-16;protect(pages,4096,PAGE_READONLY);break;
            case 7:lock=pages+4096-16;protect(pages,4096,PAGE_NOACCESS);break;
        }
        address_kind=address;entered=0;returned=0;worker_result=0xfeedface;worker_exception=0;
        HANDLE thread=CreateThread(nullptr,0,blocking_worker,nullptr,0,nullptr);if(!thread)ExitProcess(3);
        while(!InterlockedCompareExchange(&entered,0,0))Sleep(0);
        ULONG before_state=0,before_reason=0,queries=0;
        bool confirmed=false;
        for(;queries<1024;++queries) {
            if(state(before_state,before_reason)&&before_state==5&&!InterlockedCompareExchange(&returned,0,0)){confirmed=true;break;}
            if(WaitForSingleObject(thread,0)==WAIT_OBJECT_0)break;
            Sleep(0);
        }
        if(!confirmed) {
            using QueryThread=LONG(NTAPI *)(HANDLE,ULONG,void *,ULONG,ULONG *);
            auto qt=reinterpret_cast<QueryThread>(GetProcAddress(ntdll,"NtQueryInformationThread"));
            unsigned char last[32]={};ULONG got=0;LONG qs=qt?qt(thread,21,last,sizeof(last),&got):LONG(0xfeedface);
            ULONG_PTR first=0;for(unsigned i=0;i<sizeof(void *);++i)first|=ULONG_PTR(last[i])<<(i*8);
            unsigned svc=last[sizeof(void *)]|(unsigned(last[sizeof(void *)+1])<<8);
            text("unconfirmed");field(address);field(hint);field(worker_tid);field(GetThreadId(thread));field(GetCurrentProcessId());field(before_state);field(before_reason);field(queries);field(self_found);field(thread_found);field(InterlockedCompareExchange(&returned,0,0));field(worker_result);field(ULONG(qs));field(got);field(first);field(svc);flush();
            ExitProcess(14);
        }
        SetLastError(0x76543210);LONG result=LONG(0xfeedface);DWORD exception=0;
        __try {result=alert_ex(reinterpret_cast<HANDLE>(ULONG_PTR(worker_tid)),lock);}
        __except(EXCEPTION_EXECUTE_HANDLER){exception=GetExceptionCode();}
        DWORD error=GetLastError();
        if(WaitForSingleObject(thread,INFINITE)!=WAIT_OBJECT_0)ExitProcess(4);
        DWORD exit;if(!GetExitCodeThread(thread,&exit)||exit!=0x38)ExitProcess(5);
        DWORD first=protection(pages),second=protection(pages+4096);protect(pages,12288,PAGE_READWRITE);
        text("blocked");field(address);field(hint);field(ULONG(result));field(exception);field(error);
        field(worker_result);field(worker_exception);field(before_state);field(before_reason);field(queries);field(first);field(second);
        const char digits[]="0123456789abcdef";line[position++]=' ';
        for(unsigned i=4096-24;i<4096+40;++i){line[position++]=digits[pages[i]>>4];line[position++]=digits[pages[i]&15];}
        flush();if(!CloseHandle(thread))ExitProcess(6);
    }
    ExitProcess(0);
}
