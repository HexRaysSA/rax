#include <windows.h>
using Create=LONG(NTAPI*)(HANDLE*,ULONG,void*,HANDLE,void*,void*,ULONG,SIZE_T,SIZE_T,SIZE_T,void*);
using Terminate=LONG(NTAPI*)(HANDLE,LONG);
using Query=LONG(NTAPI*)(HANDLE,ULONG,void*,ULONG,ULONG*);
struct Basic { LONG status; void *teb; HANDLE pid,tid; ULONG_PTR affinity; LONG priority,base; };
static_assert(sizeof(Basic)==(sizeof(void*)==8?48:28));
static Create create;static Terminate terminate;static Query query;static void *start;
static HANDLE output;static char line[2048];static unsigned at,index;
static void text(const char*p){while(*p)line[at++]=*p++;}
static void field(ULONG_PTR v){text(" ");const char h[]="0123456789abcdef";for(unsigned n=sizeof(v)*2;n;--n)line[at++]=h[(v>>((n-1)*4))&15];}
static void flush(){text("\n");DWORD n=0;if(!WriteFile(output,line,at,&n,nullptr)||n!=at)ExitProcess(2);at=0;}
static HANDLE target(){HANDLE h=nullptr;if(create(&h,0x1fffff,nullptr,GetCurrentProcess(),start,nullptr,1,0,0,0,nullptr)<0)ExitProcess(3);return h;}
static HANDLE duplicate(HANDLE h,DWORD rights){HANDLE out=nullptr;if(!DuplicateHandle(GetCurrentProcess(),h,GetCurrentProcess(),&out,rights,FALSE,0))ExitProcess(4);return out;}
static void one(unsigned kind,DWORD access,unsigned tag,unsigned phase,LONG code){
 HANDLE h=target(),alias=nullptr,candidate=h,event=nullptr;bool alias_closed=false;
 if(kind==0){alias=duplicate(h,access);candidate=reinterpret_cast<HANDLE>(reinterpret_cast<ULONG_PTR>(alias)|tag);}
 else if(kind==1){alias=duplicate(h,0x1fffff);candidate=alias;CloseHandle(alias);alias_closed=true;}
 else if(kind==2)candidate=reinterpret_cast<HANDLE>(ULONG_PTR(0x12345678));
 else if(kind==3)candidate=GetCurrentProcess();
 else if(kind==4){event=CreateEventW(nullptr,FALSE,FALSE,nullptr);if(!event)ExitProcess(5);alias=duplicate(event,access);candidate=alias;}
 else if(kind==5){alias=duplicate(GetCurrentProcess(),access);candidate=alias;}
 if(phase){if(terminate(h,0x37)<0||WaitForSingleObject(h,INFINITE)!=WAIT_OBJECT_0)ExitProcess(6);}
 SetLastError(0x76543210);LONG status=terminate(candidate,code);DWORD last=GetLastError();
 DWORD immediate=WaitForSingleObject(h,0);LONG second=terminate(candidate,LONG(0x55667788));
 LONG cleanup=0;if(status<0)cleanup=terminate(h,0x37);
 DWORD joined=WaitForSingleObject(h,INFINITE);DWORD exitcode=0xfeed;BOOL got=GetExitCodeThread(h,&exitcode);Basic basic={};ULONG length=0xfeed;LONG queried=query(h,0,&basic,sizeof(basic),&length);
 text("case");field(index++);field(kind);field(access);field(tag);field(phase);field(ULONG(code));field(ULONG(status));field(last);field(immediate);field(ULONG(second));field(ULONG(cleanup));field(joined);field(got);field(exitcode);field(ULONG(queried));field(length);field(ULONG(basic.status));field(basic.teb!=nullptr);flush();
 if(joined!=WAIT_OBJECT_0||!got||queried<0)ExitProcess(7);
 if(alias&&!alias_closed&&!CloseHandle(alias))ExitProcess(8);if(event&&!CloseHandle(event))ExitProcess(9);if(!CloseHandle(h))ExitProcess(10);
}
struct Self {volatile LONG before,after,status;HANDLE real;DWORD rights;unsigned kind;};
static DWORD WINAPI self_worker(void*p){auto s=static_cast<Self*>(p);HANDLE h=nullptr;s->before=1;
 if(s->kind==0)h=nullptr;else if(s->kind==1)h=GetCurrentThread();else if(s->kind==2){s->real=duplicate(GetCurrentThread(),s->rights);h=s->real;}else if(s->kind==3)h=GetCurrentProcess();else h=reinterpret_cast<HANDLE>(ULONG_PTR(0x12345678));
 s->status=terminate(h,0x11223344);s->after=1;terminate(nullptr,0x37);return 0xfeed;
}
static void self_case(unsigned kind,DWORD rights){Self s={};s.kind=kind;s.rights=rights;HANDLE h=nullptr;if(create(&h,0x1fffff,nullptr,GetCurrentProcess(),reinterpret_cast<void*>(self_worker),&s,0,0,0,0,nullptr)<0)ExitProcess(11);DWORD joined=WaitForSingleObject(h,INFINITE),code=0xfeed;BOOL got=GetExitCodeThread(h,&code);text("self");field(kind);field(rights);field(s.before);field(s.after);field(ULONG(s.status));field(joined);field(got);field(code);flush();if(joined!=WAIT_OBJECT_0||!got)ExitProcess(12);if(s.real&&!CloseHandle(s.real))ExitProcess(13);if(!CloseHandle(h))ExitProcess(14);}
extern "C" __declspec(noreturn) void entry(){output=GetStdHandle(STD_OUTPUT_HANDLE);auto n=GetModuleHandleW(L"ntdll.dll");create=reinterpret_cast<Create>(GetProcAddress(n,"NtCreateThreadEx"));terminate=reinterpret_cast<Terminate>(GetProcAddress(n,"NtTerminateThread"));query=reinterpret_cast<Query>(GetProcAddress(n,"NtQueryInformationThread"));start=reinterpret_cast<void*>(GetProcAddress(n,"RtlExitUserThread"));if(!create||!terminate||!query||!start)ExitProcess(1);
 text("width");field(sizeof(void*));flush();const DWORD rights[]={0,1,2,4,8,0x10,0x18,0x20,0x40,0x80,0x800,0x100000,0x100001,0x1fffff};const LONG codes[]={0,0x103,LONG(0xc0000005)};
 for(unsigned phase=0;phase<2;++phase)for(LONG code:codes){for(DWORD access:rights)for(unsigned tag=0;tag<4;++tag)one(0,access,tag,phase,code);for(unsigned kind=1;kind<6;++kind){one(kind,0,0,phase,code);if(kind>=4)one(kind,1,0,phase,code);}}
 for(unsigned kind=0;kind<5;++kind){if(kind==2){for(DWORD access:rights)self_case(kind,access);}else self_case(kind,0);}
 text("count");field(index);flush();ExitProcess(0);
}
