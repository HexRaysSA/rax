#include <windows.h>
using Get = LONG(NTAPI *)(HANDLE, void *);
static void output(const DWORD *v,unsigned count){const char hex[]="0123456789abcdef";char text[256];unsigned at=0;for(unsigned n=0;n<count;++n){for(int shift=28;shift>=0;shift-=4)text[at++]=hex[(v[n]>>shift)&15];text[at++]=' ';}text[at++]='\n';DWORD size;if(!WriteFile(GetStdHandle(STD_OUTPUT_HANDLE),text,at,&size,nullptr)||size!=at)ExitProcess(99);}
extern "C" __declspec(noreturn) void entry(){
    auto get=reinterpret_cast<Get>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtGetContextThread"));if(!get)ExitProcess(10);
#if defined(_M_IX86)
    const DWORD tag=0x10000;
#elif defined(_M_X64)
    const DWORD tag=0x100000;
#else
    const DWORD tag=0x400000;
#endif
    for(DWORD n=0;n<32;++n){CONTEXT context={};const DWORD request=tag|(n<<27);context.ContextFlags=request;SetLastError(0x76543210);DWORD status=DWORD(get(GetCurrentThread(),&context));DWORD row[]={n,tag,request,status,context.ContextFlags,GetLastError()};output(row,6);if(status)ExitProcess(11);}
    ExitProcess(0);
}
