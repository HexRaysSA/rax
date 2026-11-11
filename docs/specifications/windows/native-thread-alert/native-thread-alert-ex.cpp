#include <windows.h>
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
static DWORD WINAPI worker(void *) {
    worker_tid=GetCurrentThreadId(); InterlockedExchange(&ready,1);
    if(WaitForSingleObject(stop_event,INFINITE)!=WAIT_OBJECT_0)return 61;
    for(unsigned i=0;i<8;++i)worker_waits[i]=poll();
    return 0x37;
}
static void boundary(unsigned phase,unsigned target_kind,unsigned pending,unsigned mode,unsigned delta) {
    for(unsigned i=0;i<3;++i)poll();
    protect(pages,12288,PAGE_READWRITE);
    for(unsigned i=0;i<12288;++i)pages[i]=0;
    auto ptr=pages+4096-(mode==7||mode==8?1:16)+delta;
    if(mode==0)ptr=nullptr;
    if(mode==2)ptr=reinterpret_cast<unsigned char *>(ULONG_PTR(1));
    if(mode==9)ptr=reinterpret_cast<unsigned char *>(~ULONG_PTR(0));
    if(mode==3)protect(pages,4096,PAGE_READONLY);
    if(mode==4)protect(pages,4096,PAGE_NOACCESS);
    if(mode==5)protect(pages,4096,PAGE_READWRITE|PAGE_GUARD);
    if(mode==6)protect(pages,4096,PAGE_READONLY|PAGE_GUARD);
    if(mode==8)protect(pages+4096,4096,PAGE_NOACCESS);
    ULONG_PTR target=0;
    switch(target_kind) {
      case 0:target=GetCurrentThreadId();break;
      case 1:target=worker_tid;break;
      case 2:target=0;break;
      case 3:target=GetCurrentProcessId();break;
      case 4:target=ULONG_PTR(GetCurrentThreadId())|1;break;
      case 5:target=ULONG_PTR(worker_tid)|1;break;
    }
    ULONG seeded=0xfeedface;
    if(pending)seeded=ULONG(alert_id(reinterpret_cast<HANDLE>(ULONG_PTR(GetCurrentThreadId()))));
    SetLastError(0x76543210);LONG result=LONG(0xfeedface);DWORD exception=0;
    __try {result=alert_ex(reinterpret_cast<HANDLE>(target),ptr);}
    __except(EXCEPTION_EXECUTE_HANDLER){exception=GetExceptionCode();}
    DWORD error=GetLastError();DWORD first=protection(pages),second=protection(pages+4096);
    protect(pages,12288,PAGE_READWRITE);
    text("case");field(case_index++);field(phase);field(target_kind);field(pending);field(mode);field(delta);field(seeded);
    field(ULONG(result));field(exception);field(error);field(first);field(second);
    for(unsigned i=0;i<3;++i)field(poll());
    line[position++]=' ';
    const char digits[]="0123456789abcdef";
    for(unsigned i=4096-24;i<4096+40;++i){line[position++]=digits[pages[i]>>4];line[position++]=digits[pages[i]&15];}
    flush();
}
extern "C" __declspec(noreturn) void entry() {
    output=GetStdHandle(STD_OUTPUT_HANDLE);auto ntdll=GetModuleHandleW(L"ntdll.dll");
    alert_id=reinterpret_cast<AlertId>(GetProcAddress(ntdll,"NtAlertThreadByThreadId"));
    alert_ex=reinterpret_cast<AlertEx>(GetProcAddress(ntdll,"NtAlertThreadByThreadIdEx"));
    wait_id=reinterpret_cast<WaitId>(GetProcAddress(ntdll,"NtWaitForAlertByThreadId"));
    if(!alert_id||!alert_ex||!wait_id)ExitProcess(1);
    pages=static_cast<unsigned char *>(VirtualAlloc(nullptr,12288,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE));
    stop_event=CreateEventW(nullptr,TRUE,FALSE,nullptr);if(!pages||!stop_event)ExitProcess(2);
    HANDLE thread=CreateThread(nullptr,0,worker,nullptr,0,nullptr);if(!thread)ExitProcess(3);
    while(!InterlockedCompareExchange(&ready,0,0))Sleep(0);
    text("width");field(sizeof(void *));flush();
    text("stub");for(unsigned i=0;i<32;++i)field(reinterpret_cast<unsigned char *>(alert_ex)[i]);flush();
    const unsigned deltas[]={0,1,4,7};
    for(unsigned phase=0;phase<2;++phase) {
        if(phase) {
            if(!SetEvent(stop_event)||WaitForSingleObject(thread,INFINITE)!=WAIT_OBJECT_0)ExitProcess(4);
            DWORD exit;if(!GetExitCodeThread(thread,&exit)||exit!=0x37)ExitProcess(5);
            text("worker");field(exit);for(ULONG status:worker_waits)field(status);flush();
        }
        for(unsigned target=0;target<6;++target)for(unsigned pending=0;pending<2;++pending)
          for(unsigned mode=0;mode<10;++mode)for(unsigned delta:deltas)boundary(phase,target,pending,mode,delta);
    }
    if(!CloseHandle(thread)||!CloseHandle(stop_event))ExitProcess(6);
    text("count");field(case_index);flush();ExitProcess(0);
}
