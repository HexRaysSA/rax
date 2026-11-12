#include <windows.h>
static DWORD worker_id;
static CONTEXT saved_full;
static ULONG_PTR target;
static volatile LONG traps;
static volatile DWORD saved_flags, copied, read_ok;
static volatile ULONG_PTR saved_pc, saved_sp, initial_pc;
static volatile ULONG_PTR saved_bcr0,saved_bvr0;
static LONG CALLBACK handler(EXCEPTION_POINTERS *e) {
    if (GetCurrentThreadId()!=worker_id || e->ContextRecord->Pc!=target ||
        e->ExceptionRecord->ExceptionCode!=EXCEPTION_BREAKPOINT) return EXCEPTION_CONTINUE_SEARCH;
    CONTEXT &original=saved_full;SIZE_T count=0;
    read_ok=ReadProcessMemory(GetCurrentProcess(),reinterpret_cast<void*>(e->ContextRecord->X0),&original,sizeof(original),&count);
    copied=DWORD(count);saved_bcr0=original.Bcr[0];saved_bvr0=original.Bvr[0];saved_flags=original.ContextFlags;saved_pc=ULONG_PTR(original.Pc);saved_sp=ULONG_PTR(original.Sp);
    e->ContextRecord->ContextFlags|=CONTEXT_DEBUG_REGISTERS;e->ContextRecord->Bcr[0]=0;
    InterlockedIncrement(&traps);return EXCEPTION_CONTINUE_EXECUTION;
}
static DWORD WINAPI worker(void*) { return 0x53000000; }
extern "C" __declspec(noreturn) void entry() {
    target=ULONG_PTR(GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"LdrInitializeThunk"));
    PVOID registration=AddVectoredExceptionHandler(1,handler);if(!target || !registration)ExitProcess(70);
    HANDLE thread=CreateThread(nullptr,0,worker,nullptr,CREATE_SUSPENDED,&worker_id);if(!thread)ExitProcess(71);
    CONTEXT before={};before.ContextFlags=CONTEXT_CONTROL|CONTEXT_INTEGER|CONTEXT_DEBUG_REGISTERS;
    DWORD get_ok=GetThreadContext(thread,&before);initial_pc=ULONG_PTR(before.Pc);
    CONTEXT set={};set.ContextFlags=CONTEXT_DEBUG_REGISTERS;set.Bvr[0]=target;set.Bcr[0]=0x1e5;
    DWORD set_ok=SetThreadContext(thread,&set);DWORD previous=ResumeThread(thread);DWORD wait=WaitForSingleObject(thread,30000);DWORD result=0;GetExitCodeThread(thread,&result);
    ULONG_PTR values[]={get_ok,set_ok,previous,wait,result,DWORD(traps),read_ok,copied,saved_flags,saved_pc,saved_sp,initial_pc,target,saved_bcr0,saved_bvr0,saved_full.Bcr[0],saved_full.Bcr[1],saved_full.Bcr[2],saved_full.Bcr[3],saved_full.Bcr[4],saved_full.Bcr[5],saved_full.Bcr[6],saved_full.Bcr[7],saved_full.Wcr[0],saved_full.Wcr[1]};
    char text[25*17];const char hex[]="0123456789abcdef";unsigned at=0;
    for(unsigned i=0;i<25;++i){unsigned long long value=values[i];for(int shift=60;shift>=0;shift-=4)text[at++]=hex[(value>>shift)&15];text[at++]=i==24?'\n':' ';}
    DWORD written=0;WriteFile(GetStdHandle(STD_OUTPUT_HANDLE),text,at,&written,nullptr);
    if(wait==WAIT_OBJECT_0)CloseHandle(thread);RemoveVectoredExceptionHandler(registration);
    ExitProcess(get_ok && set_ok && previous==1 && wait==WAIT_OBJECT_0 && result==0x53000000 && traps==1 && read_ok && copied==sizeof(CONTEXT) ? 0 : 77);
}
