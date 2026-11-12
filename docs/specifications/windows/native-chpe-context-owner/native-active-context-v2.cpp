#include <windows.h>

extern "C" __declspec(dllexport) volatile LONG rax_thread_object_state[64] = {0x52415854};
static HANDLE release_event;
static DWORD process_id;
static INIT_ONCE once = INIT_ONCE_STATIC_INIT;
static LONG callback_cookie;

static void report() {
    static const char digits[] = "0123456789abcdef";
    char text[6 + 64 * 9];
    text[0]='s'; text[1]='t'; text[2]='a'; text[3]='t'; text[4]='e'; text[5]=' ';
    unsigned at=6;
    for(unsigned index=0;index<64;++index){
        DWORD value=DWORD(rax_thread_object_state[index]);
        for(int shift=28;shift>=0;shift-=4)text[at++]=digits[(value>>shift)&15];
        text[at++]=index==63?'\n':' ';
    }
    DWORD written=0;
    WriteFile(GetStdHandle(STD_OUTPUT_HANDLE),text,at,&written,nullptr);
}
static void check(bool value,LONG stage){
    if(!value){rax_thread_object_state[6]=stage;rax_thread_object_state[8]=GetLastError();report();ExitProcess(70);}
    InterlockedIncrement(&rax_thread_object_state[10]);
}
static ULONG_PTR context_pc(const CONTEXT &context){
#if defined(_M_ARM64)
    return ULONG_PTR(context.Pc);
#elif defined(_M_X64)
    return ULONG_PTR(context.Rip);
#else
    return ULONG_PTR(context.Eip);
#endif
}
static ULONG_PTR context_sp(const CONTEXT &context){
#if defined(_M_ARM64)
    return ULONG_PTR(context.Sp);
#elif defined(_M_X64)
    return ULONG_PTR(context.Rsp);
#else
    return ULONG_PTR(context.Esp);
#endif
}
static BOOL CALLBACK initialize(PINIT_ONCE, PVOID parameter, PVOID *result){
    check(parameter==&callback_cookie,200);
    InterlockedIncrement(&rax_thread_object_state[12]);
    *result=parameter;
    return TRUE;
}
static DWORD WINAPI worker(void *parameter){
    check(GetCurrentProcessId()==process_id,100);
    check(GetCurrentThreadId()!=DWORD(rax_thread_object_state[16]),101);
    SetLastError(0x12345678);
    check(GetLastError()==0x12345678,102);
    check(WaitForSingleObject(release_event,INFINITE)==WAIT_OBJECT_0,103);
    CONTEXT local={};
    RtlCaptureContext(&local);
    check(context_pc(local)!=0 && context_sp(local)!=0,104);
    check((context_sp(local)&(sizeof(void*)-1))==0,105);
    PVOID result=nullptr;
    check(InitOnceExecuteOnce(&once,initialize,&callback_cookie,&result)!=FALSE,106);
    check(result==&callback_cookie,107);
    return DWORD(ULONG_PTR(parameter));
}
extern "C" __declspec(noreturn) void entry(){
    process_id=GetCurrentProcessId();
    rax_thread_object_state[16]=LONG(GetCurrentThreadId());
    CONTEXT own={};
    RtlCaptureContext(&own);
    check(context_pc(own)!=0 && context_sp(own)!=0,1);
    release_event=CreateEventW(nullptr,TRUE,FALSE,nullptr);
    check(release_event!=nullptr,2);
    for(unsigned index=0;index<4;++index){
        check(ResetEvent(release_event)!=FALSE,10);
        DWORD tid=0;
        DWORD cookie=0x53000000+index;
        HANDLE thread=CreateThread(nullptr,0,worker,reinterpret_cast<void*>(ULONG_PTR(cookie)),CREATE_SUSPENDED,&tid);
        check(thread!=nullptr && tid!=0 && tid!=DWORD(rax_thread_object_state[16]),11);
        CONTEXT saved={};saved.ContextFlags=CONTEXT_FULL;
        check(GetThreadContext(thread,&saved)!=FALSE,12);
        check(context_pc(saved)!=0 && context_sp(saved)!=0,13);
        check(SetThreadContext(thread,&saved)!=FALSE,14);
        check(SetEvent(release_event)!=FALSE,15);
        check(ResumeThread(thread)==1,16);
        check(WaitForSingleObject(thread,INFINITE)==WAIT_OBJECT_0,17);
        DWORD result=0;
        check(GetExitCodeThread(thread,&result)!=FALSE && result==cookie,18);
        check(CloseHandle(thread)!=FALSE,19);
        rax_thread_object_state[1]=LONG(index+1);
    }
    PVOID result=nullptr;
    check(InitOnceExecuteOnce(&once,initialize,&callback_cookie,&result)!=FALSE && result==&callback_cookie,30);
    check(rax_thread_object_state[12]==1,31);
    check(CloseHandle(release_event)!=FALSE,32);
    report();
    ExitProcess(0);
}
