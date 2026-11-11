#include <windows.h>
#ifndef PROBE_FLAGS
#define PROBE_FLAGS 3
#endif
struct Result { ULONG flags, created, resumed, previous, waited, entered; HANDLE thread; };
static Result result;
static volatile LONG reached;
using Create=LONG(NTAPI*)(HANDLE*,ULONG,void*,HANDLE,void*,void*,ULONG,SIZE_T,SIZE_T,SIZE_T,void*);
using Resume=LONG(NTAPI*)(HANDLE,ULONG*);
using Terminate=LONG(NTAPI*)(HANDLE,LONG);
static Terminate terminate;
static DWORD WINAPI worker(void*){InterlockedExchange(&reached,1);terminate(GetCurrentThread(),0x37);return 0xfeed;}
extern "C" BOOL WINAPI dll_entry(HINSTANCE,DWORD reason,void*){
 if(reason!=DLL_PROCESS_ATTACH)return TRUE;
 auto n=GetModuleHandleW(L"ntdll.dll");auto create=reinterpret_cast<Create>(GetProcAddress(n,"NtCreateThreadEx"));auto resume=reinterpret_cast<Resume>(GetProcAddress(n,"NtResumeThread"));terminate=reinterpret_cast<Terminate>(GetProcAddress(n,"NtTerminateThread"));
 if(!create||!resume||!terminate)return FALSE;
 result.flags=PROBE_FLAGS;result.created=create(&result.thread,0x1fffff,nullptr,GetCurrentProcess(),reinterpret_cast<void*>(worker),nullptr,PROBE_FLAGS,0,0,0,nullptr);
 if(LONG(result.created)<0)return FALSE;
 result.resumed=resume(result.thread,&result.previous);result.waited=WaitForSingleObject(result.thread,500);result.entered=InterlockedCompareExchange(&reached,0,0);return TRUE;
}
extern "C" __declspec(dllexport) Result *get_init_result(){return &result;}
