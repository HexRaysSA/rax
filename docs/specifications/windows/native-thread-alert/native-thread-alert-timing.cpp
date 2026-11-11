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

static volatile LONG command;
static ULONG waited, caught;
static unsigned wait_address;
static LARGE_INTEGER worker_timeout;
static DWORD WINAPI blocking_worker(void *) {
    worker_tid = GetCurrentThreadId();
    InterlockedExchange(&ready, 1);
    if (WaitForSingleObject(stop_event, INFINITE) != WAIT_OBJECT_0) return 61;
    void *address = wait_address == 0 ? nullptr : wait_address == 1 ? reinterpret_cast<void *>(ULONG_PTR(1)) : wait_address == 2 ? reinterpret_cast<void *>(~ULONG_PTR(0)) : static_cast<void *>(pages);
    InterlockedExchange(&command, 1);
    __try { waited = ULONG(wait_id(address, &worker_timeout)); }
    __except (EXCEPTION_EXECUTE_HANDLER) { caught = GetExceptionCode(); }
    return 0x38;
}
extern "C" __declspec(noreturn) void entry() {
    output = GetStdHandle(STD_OUTPUT_HANDLE);
    auto ntdll = GetModuleHandleW(L"ntdll.dll");
    alert_id = reinterpret_cast<AlertId>(GetProcAddress(ntdll, "NtAlertThreadByThreadId"));
    wait_id = reinterpret_cast<WaitId>(GetProcAddress(ntdll, "NtWaitForAlertByThreadId"));
    if (!alert_id || !wait_id) ExitProcess(1);
    pages = static_cast<unsigned char *>(VirtualAlloc(nullptr, 12288, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!pages) ExitProcess(2);
    text("width"); field(sizeof(void *)); flush();
    text("alert-bytes"); for(unsigned i=0;i<128;++i) field(reinterpret_cast<unsigned char *>(alert_id)[i]); flush();
    text("wait-bytes"); for(unsigned i=0;i<128;++i) field(reinterpret_cast<unsigned char *>(wait_id)[i]); flush();
    const LONGLONG values[] = {0, -1, -10000, 1, 0x7fffffffffffffffLL, LONGLONG(0x8000000000000000ULL)};
    for(unsigned pending=0;pending<3;++pending) for(unsigned kind=0;kind<7;++kind) {
        if (!pending && kind>=4) continue;
        for(unsigned i=0;i<3;++i) poll();
        for(unsigned i=0;i<pending;++i) if(alert_id(reinterpret_cast<HANDLE>(ULONG_PTR(GetCurrentThreadId())))!=0) ExitProcess(3);
        LARGE_INTEGER timeout; timeout.QuadPart = values[kind<6?kind:0];
        DWORD error=0; ULONG status=0xfeedface;
        SetLastError(0x76543210);
        __try { status=ULONG(wait_id(reinterpret_cast<void *>(ULONG_PTR(1)),kind==6?nullptr:&timeout)); }
        __except(EXCEPTION_EXECUTE_HANDLER) { error=GetExceptionCode(); }
        DWORD last=GetLastError();
        text("deadline");field(pending);field(kind);field(status);field(error);field(last);field(poll());flush();
    }
    for(unsigned address=0;address<4;++address) for(unsigned absolute=0;absolute<2;++absolute) for(unsigned tag=0;tag<4;++tag) {
        ready=0;command=0;waited=0xfeedface;caught=0;wait_address=address;
        stop_event=CreateEventW(nullptr,TRUE,FALSE,nullptr);
        worker_timeout.QuadPart=-5000000;
        if(absolute){FILETIME now;GetSystemTimeAsFileTime(&now);worker_timeout.LowPart=now.dwLowDateTime;worker_timeout.HighPart=LONG(now.dwHighDateTime);worker_timeout.QuadPart+=5000000;}
        HANDLE thread=CreateThread(nullptr,0,blocking_worker,nullptr,0,nullptr);if(!thread)ExitProcess(4);
        while(!InterlockedCompareExchange(&ready,0,0))Sleep(0);
        SetEvent(stop_event);while(!InterlockedCompareExchange(&command,0,0))Sleep(0);
        Sleep(5);
        ULONG alert=ULONG(alert_id(reinterpret_cast<HANDLE>(ULONG_PTR(worker_tid)|tag)));
        if(WaitForSingleObject(thread,INFINITE)!=WAIT_OBJECT_0)ExitProcess(5);
        DWORD exit; if(!GetExitCodeThread(thread,&exit)||exit!=0x38)ExitProcess(6);
        text("blocked");field(address);field(absolute);field(tag);field(alert);field(waited);field(caught);field(exit);flush();
        if(!CloseHandle(thread)||!CloseHandle(stop_event))ExitProcess(7);
    }
    // Invalid IDs are exclusively values disjoint from live thread CID alignment,
    // our own process ID, and our own tagged current ID.
    for(unsigned kind=0;kind<5;++kind) {
        ULONG_PTR id=kind<3?kind:kind==3?ULONG_PTR(GetCurrentProcessId()):ULONG_PTR(GetCurrentThreadId())|1;
        text("invalid");field(kind);field(ULONG(alert_id(reinterpret_cast<HANDLE>(id))));field(poll());flush();
    }
    ExitProcess(0);
}
