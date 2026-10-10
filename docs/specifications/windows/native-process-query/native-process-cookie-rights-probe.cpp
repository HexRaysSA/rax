#include <windows.h>
#include <cstdio>
#include <cstring>
#include <initializer_list>
using Q=LONG(NTAPI*)(HANDLE,ULONG,void*,ULONG,ULONG*);
int main(int argc,char** argv){if(argc>1)return 0;auto q=reinterpret_cast<Q>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtQueryInformationProcess"));
for(DWORD access:std::initializer_list<DWORD>{0x8u,0x20u,0x28u,0x30u,0x38u,0x410u,0x420u,0x428u,0x430u,0x438u,0x1020u,0x1030u,0x1420u,0x1430u,0x1fffffu & ~0x20u,0x1fffffu & ~0x10u,0x1fffffu & ~0x400u}){auto h=OpenProcess(access,FALSE,GetCurrentProcessId());ULONG out=0xa5a5a5a5,ret=0xa5a5a5a5;auto s=q(h,36,&out,4,&ret);printf("access=%08lX opened=%d status=%08lX out=%08lX returned=%08lX\n",access,h!=nullptr,s,out,ret);if(h)CloseHandle(h);}
wchar_t exe[32768];GetModuleFileNameW(nullptr,exe,32768);wchar_t args[32768];swprintf_s(args,L"\"%s\" --child",exe);STARTUPINFOW si{sizeof(si)};PROCESS_INFORMATION pi{};if(!CreateProcessW(exe,args,nullptr,nullptr,FALSE,CREATE_SUSPENDED,nullptr,nullptr,&si,&pi))return 2;ULONG out=0xa5a5a5a5,ret=0xa5a5a5a5;auto s=q(pi.hProcess,36,&out,4,&ret);printf("foreign-created-process status=%08lX out=%08lX returned=%08lX\n",s,out,ret);TerminateProcess(pi.hProcess,0);WaitForSingleObject(pi.hProcess,1000);CloseHandle(pi.hThread);CloseHandle(pi.hProcess);
auto p=static_cast<unsigned char*>(VirtualAlloc(nullptr,8192,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE));DWORD old;
for(int role:{0,1}){VirtualProtect(p,8192,PAGE_READWRITE,&old);memset(p,0xa5,8192);VirtualProtect(p+role*4096,4096,PAGE_READWRITE|PAGE_GUARD,&old);DWORD exception=0;LONG status=0;__try{status=q(GetCurrentProcess(),36,p,4,reinterpret_cast<ULONG*>(p+4096));}__except(EXCEPTION_EXECUTE_HANDLER){exception=GetExceptionCode();}MEMORY_BASIC_INFORMATION mi{};VirtualQuery(p+role*4096,&mi,sizeof(mi));VirtualProtect(p,8192,PAGE_READWRITE,&old);printf("guard=%d status=%08lX exception=%08lX protection=%08lX out=%08lX returned=%08lX\n",role,status,exception,mi.Protect,*reinterpret_cast<ULONG*>(p),*reinterpret_cast<ULONG*>(p+4096));}
VirtualFree(p,0,MEM_RELEASE);
for(unsigned at:{0u,1u,2u,3u,4u}){alignas(16)unsigned char b[32];memset(b,0xa5,32);auto s=q(GetCurrentProcess(),36,b,4,reinterpret_cast<ULONG*>(b+at));printf("alias=%u status=%08lX bytes=",at,s);for(unsigned i=0;i<8;i++)printf("%02x",b[i]);putchar('\n');}
}
