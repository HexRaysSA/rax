#include <windows.h>
using Create = LONG(NTAPI *)(HANDLE *, ULONG, void *, HANDLE, void *, void *, ULONG, SIZE_T, SIZE_T, SIZE_T, void *);
using Resume = LONG(NTAPI *)(HANDLE, ULONG *);
using Terminate = LONG(NTAPI *)(HANDLE, LONG);
using Lock = LONG(NTAPI *)(ULONG, ULONG *, ULONG_PTR *);
using Unlock = LONG(NTAPI *)(ULONG, ULONG_PTR);
static Terminate terminate;
static volatile LONG entered;
static HANDLE output;
static char line[1024];
static unsigned at;
static void text(const char *p) { while (*p) line[at++] = *p++; }
static void field(ULONG_PTR value) { text(" "); const char h[]="0123456789abcdef"; for(unsigned n=sizeof(value)*2;n;--n)line[at++]=h[(value>>((n-1)*4))&15]; }
static void flush() { text("\n");DWORD n=0;if(!WriteFile(output,line,at,&n,nullptr)||n!=at)ExitProcess(2);at=0; }
static DWORD WINAPI worker(void *) { InterlockedExchange(&entered,1);terminate(GetCurrentThread(),0x37);return 0xfeed; }
extern "C" __declspec(noreturn) void entry() {
    output=GetStdHandle(STD_OUTPUT_HANDLE);auto n=GetModuleHandleW(L"ntdll.dll");
    auto create=reinterpret_cast<Create>(GetProcAddress(n,"NtCreateThreadEx"));
    auto resume=reinterpret_cast<Resume>(GetProcAddress(n,"NtResumeThread"));
    terminate=reinterpret_cast<Terminate>(GetProcAddress(n,"NtTerminateThread"));
    auto lock=reinterpret_cast<Lock>(GetProcAddress(n,"LdrLockLoaderLock"));
    auto unlock=reinterpret_cast<Unlock>(GetProcAddress(n,"LdrUnlockLoaderLock"));
    if(!create||!resume||!terminate||!lock||!unlock)ExitProcess(1);
    const ULONG flags[]={1,3,5,7
#if defined(_M_ARM64)
        ,0x21,0x23,0x25,0x27
#endif
    };
    text("width");field(sizeof(void*));flush();
    for(ULONG f:flags){
        ULONG state=0;ULONG_PTR cookie=0;LONG locked=lock(0,&state,&cookie);if(locked<0)ExitProcess(3);
        InterlockedExchange(&entered,0);HANDLE thread=nullptr;LONG created=create(&thread,0x1fffff,nullptr,GetCurrentProcess(),reinterpret_cast<void*>(worker),nullptr,f,0,0,0,nullptr);
        if(created<0){unlock(0,cookie);ExitProcess(4);}
        ULONG previous=0;LONG resumed=resume(thread,&previous);DWORD held=WaitForSingleObject(thread,500);LONG before=InterlockedCompareExchange(&entered,0,0);
        LONG released=unlock(0,cookie);DWORD joined=WaitForSingleObject(thread,INFINITE);DWORD code=0;BOOL got=GetExitCodeThread(thread,&code);BOOL closed=CloseHandle(thread);
        text("case");field(f);field(ULONG(locked));field(state);field(ULONG(created));field(ULONG(resumed));field(previous);field(held);field(before);field(ULONG(released));field(joined);field(got);field(code);field(closed);flush();
        if(resumed<0||released<0||joined!=WAIT_OBJECT_0||!got||code!=0x37||!closed)ExitProcess(5);
    }
    ExitProcess(0);
}
