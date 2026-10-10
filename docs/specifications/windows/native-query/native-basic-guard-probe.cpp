#include <windows.h>
#include <cstdio>
#include <cstring>
using Query = LONG(NTAPI*)(ULONG, void*, ULONG, ULONG*);
int main(){
 auto q=reinterpret_cast<Query>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtQuerySystemInformation"));if(!q)return 1;
 auto p=static_cast<unsigned char*>(VirtualAlloc(nullptr,8192,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE));if(!p)return 2;
 for(int guard_return=0;guard_return<2;guard_return++){
   DWORD old;VirtualProtect(p,8192,PAGE_READWRITE,&old);memset(p,0xa5,8192);
   VirtualProtect(p+(guard_return?4096:0),4096,PAGE_READWRITE|PAGE_GUARD,&old);
   LONG status=0;DWORD exception=0;
   __try {status=q(0,p,(sizeof(void*)==4?44:64),reinterpret_cast<ULONG*>(p+4096));} __except(EXCEPTION_EXECUTE_HANDLER){exception=GetExceptionCode();}
   MEMORY_BASIC_INFORMATION mbi{};VirtualQuery(p+(guard_return?4096:0),&mbi,sizeof(mbi));
   printf("returnguard=%d status=%08lX exception=%08lX protection=%08lX\n",guard_return,status,exception,mbi.Protect);
   VirtualProtect(p,8192,PAGE_READWRITE,&old);printf("output=");for(unsigned i=0;i<8;i++)printf("%02x",p[i]);printf(" returned=%08lX\n",*reinterpret_cast<ULONG*>(p+4096));
 }
 VirtualFree(p,0,MEM_RELEASE);
}
