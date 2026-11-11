#include <windows.h>
struct Result { ULONG flags, created, resumed, previous, waited, entered; HANDLE thread; };
extern "C" __declspec(dllimport) Result *get_init_result();
static char line[1024];static unsigned at;
static void text(const char*p){while(*p)line[at++]=*p++;}
static void field(ULONG_PTR v){text(" ");const char h[]="0123456789abcdef";for(unsigned n=sizeof(v)*2;n;--n)line[at++]=h[(v>>((n-1)*4))&15];}
extern "C" __declspec(noreturn) void entry(){auto r=get_init_result();DWORD joined=WaitForSingleObject(r->thread,INFINITE),code=0;BOOL got=GetExitCodeThread(r->thread,&code),closed=CloseHandle(r->thread);text("case");field(sizeof(void*));field(r->flags);field(r->created);field(r->resumed);field(r->previous);field(r->waited);field(r->entered);field(joined);field(got);field(code);field(closed);text("\n");DWORD n=0;if(!WriteFile(GetStdHandle(STD_OUTPUT_HANDLE),line,at,&n,nullptr)||n!=at)ExitProcess(2);ExitProcess(joined==WAIT_OBJECT_0&&got&&code==0x37&&closed?0:3);}
