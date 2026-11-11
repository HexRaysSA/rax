#include <windows.h>
using Clear = LONG(NTAPI *)(HANDLE);
using State = LONG(NTAPI *)(HANDLE,LONG*);
using QueryEvent = LONG(NTAPI *)(HANDLE,ULONG,void*,ULONG,ULONG*);
using QueryObject = LONG(NTAPI *)(HANDLE,ULONG,void*,ULONG,ULONG*);
struct EventInfo { LONG type,state; };
static Clear clear_event;
static State set_event,reset_event;
static QueryEvent query_event;
static QueryObject query_object;
static ULONG index_row;
static const DWORD error_marker=0x76543210;
static void check(bool value,UINT stage){if(!value)ExitProcess(stage);}
static void line(const ULONG *values,unsigned count){
    static const char digits[]="0123456789abcdef";
    char text[5+24*9];unsigned at=0;
    text[at++]='c';text[at++]='a';text[at++]='s';text[at++]='e';text[at++]=' ';
    for(unsigned i=0;i<count;++i){for(int s=28;s>=0;s-=4)text[at++]=digits[(values[i]>>s)&15];text[at++]=i+1==count?'\n':' ';}
    DWORD written=0;check(WriteFile(GetStdHandle(STD_OUTPUT_HANDLE),text,at,&written,nullptr)!=FALSE&&written==at,99);
}
static ULONG grant(HANDLE handle){
    ULONG data[64]={},length=0;
    ULONG status=ULONG(query_object(handle,0,data,56,&length));
    if(status!=0){ULONG diagnostic[]={0xffffffff,status,length,56};line(diagnostic,4);ExitProcess(90);}
    return data[1];
}
static void row(ULONG category,ULONG kind,ULONG seed,ULONG access,ULONG granted,ULONG tag,HANDLE target,HANDLE base){
    EventInfo before={-1,-1},after={-1,-1},repeat={-1,-1};ULONG length=0;
    ULONG qb=0xffffffff,qa=0xffffffff;
    if(base){check((seed?set_event(base,nullptr):reset_event(base,nullptr))==0,91);qb=ULONG(query_event(base,0,&before,sizeof(before),&length));check(qb==0&&length==sizeof(before),92);}
    HANDLE tagged=reinterpret_cast<HANDLE>(ULONG_PTR(target)|tag);
    SetLastError(error_marker);ULONG status=ULONG(clear_event(tagged));ULONG last=GetLastError();
    if(base){qa=ULONG(query_event(base,0,&after,sizeof(after),&length));check(qa==0,93);}
    ULONG again=ULONG(clear_event(tagged));
    if(base)check(query_event(base,0,&repeat,sizeof(repeat),&length)==0,94);
    ULONG values[]={index_row++,category,kind,seed,access,granted,tag,status,last,qb,ULONG(before.type),ULONG(before.state),qa,ULONG(after.type),ULONG(after.state),again,ULONG(repeat.state)};
    line(values,sizeof(values)/sizeof(values[0]));
}
extern "C" __declspec(noreturn) void entry(){
    HMODULE ntdll=GetModuleHandleW(L"ntdll.dll");
    clear_event=reinterpret_cast<Clear>(GetProcAddress(ntdll,"NtClearEvent"));
    set_event=reinterpret_cast<State>(GetProcAddress(ntdll,"NtSetEvent"));
    reset_event=reinterpret_cast<State>(GetProcAddress(ntdll,"NtResetEvent"));
    query_event=reinterpret_cast<QueryEvent>(GetProcAddress(ntdll,"NtQueryEvent"));
    query_object=reinterpret_cast<QueryObject>(GetProcAddress(ntdll,"NtQueryObject"));
    check(clear_event&&set_event&&reset_event&&query_event&&query_object,10);
    const ULONG rights[]={0,1,2,3,0x100000,0x100001,0x100002,0x1f0003,0x80000000,0x40000000,0x20000000,0x10000000};
    for(ULONG kind=0;kind<2;++kind){
        HANDLE base=CreateEventW(nullptr,kind==0,FALSE,nullptr);check(base!=nullptr,11);
        for(ULONG seed=0;seed<2;++seed)for(ULONG access:rights){
            HANDLE target=nullptr;check(DuplicateHandle(GetCurrentProcess(),base,GetCurrentProcess(),&target,access,FALSE,0)!=FALSE,12);
            ULONG granted=grant(target);
            for(ULONG tag=0;tag<4;++tag)row(0,kind,seed,access,granted,tag,target,base);
            check(CloseHandle(target)!=FALSE,13);
        }
        for(ULONG seed=0;seed<2;++seed){
            HANDLE target=nullptr;check(DuplicateHandle(GetCurrentProcess(),base,GetCurrentProcess(),&target,3,FALSE,0)!=FALSE,14);
            check(CloseHandle(target)!=FALSE,15);
            // No handle allocation occurs before the stale value is exercised.
            for(ULONG tag=0;tag<4;++tag)row(3,kind,seed,3,3,tag,target,base);
        }
        check(CloseHandle(base)!=FALSE,16);
    }
    HANDLE sources[]={CreateSemaphoreW(nullptr,0,2,nullptr),CreateMutexW(nullptr,FALSE,nullptr),GetCurrentProcess(),GetCurrentThread()};
    const ULONG wrong_rights[]={0,1,2,0x100000};
    for(ULONG kind=0;kind<4;++kind){
        check(sources[kind]!=nullptr,17);
        for(ULONG access:wrong_rights){
            HANDLE target=nullptr;check(DuplicateHandle(GetCurrentProcess(),sources[kind],GetCurrentProcess(),&target,access,FALSE,0)!=FALSE,18);
            ULONG granted=grant(target);
            for(ULONG tag=0;tag<4;++tag)row(1,kind,0,access,granted,tag,target,nullptr);
            check(CloseHandle(target)!=FALSE,19);
        }
    }
    check(CloseHandle(sources[0])!=FALSE&&CloseHandle(sources[1])!=FALSE,20);
    HANDLE invalids[]={nullptr,reinterpret_cast<HANDLE>(ULONG_PTR(1)),reinterpret_cast<HANDLE>(ULONG_PTR(2)),reinterpret_cast<HANDLE>(ULONG_PTR(3)),GetCurrentProcess(),GetCurrentThread()};
    for(ULONG kind=0;kind<6;++kind)row(2,kind,0,0,0,0,invalids[kind],nullptr);
    check(index_row==278,21);
    ExitProcess(0);
}
