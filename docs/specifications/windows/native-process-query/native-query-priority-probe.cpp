#include <windows.h>
#include <cstdio>
#include <cstring>
#include <initializer_list>
using S=LONG(NTAPI*)(ULONG,void*,ULONG,ULONG*);using P=LONG(NTAPI*)(HANDLE,ULONG,void*,ULONG,ULONG*);
int main(){auto n=GetModuleHandleW(L"ntdll.dll");auto s=reinterpret_cast<S>(GetProcAddress(n,"NtQuerySystemInformation"));auto q=reinterpret_cast<P>(GetProcAddress(n,"NtQueryInformationProcess"));auto p=static_cast<unsigned char*>(VirtualAlloc(nullptr,8192,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE));DWORD old;
for(unsigned cls:{0u,50u,36u})for(unsigned role:{0u,1u,2u,3u,4u,5u}){VirtualProtect(p,8192,PAGE_READWRITE,&old);memset(p,0xa5,8192);auto ret=reinterpret_cast<ULONG*>(role==0?reinterpret_cast<void*>(1):p+4096);void* out=p+(role==0||role==1?1:0);ULONG len=cls==0?(sizeof(void*)==4?44:64):cls==50?sizeof(void*):4;
if(role==1)VirtualProtect(p+4096,4096,PAGE_READWRITE|PAGE_GUARD,&old);if(role==2){VirtualProtect(p,4096,PAGE_READWRITE|PAGE_GUARD,&old);VirtualProtect(p+4096,4096,PAGE_READONLY,&old);}if(role==3){VirtualProtect(p+4096,4096,PAGE_READWRITE|PAGE_GUARD,&old);len--;}if(role==4){out=nullptr;len=0;ret=reinterpret_cast<ULONG*>(1);}if(role==5){VirtualProtect(p,4096,PAGE_READONLY,&old);len--;}
auto status=cls==36?q(GetCurrentProcess(),cls,out,len,ret):s(cls,out,len,ret);MEMORY_BASIC_INFORMATION a{},b{};VirtualQuery(p,&a,sizeof(a));VirtualQuery(p+4096,&b,sizeof(b));printf("pointer=%zu class=%u role=%u len=%lu status=%08lX output_protect=%08lX returned_protect=%08lX\n",sizeof(void*),cls,role,len,status,a.Protect,b.Protect);}VirtualFree(p,0,MEM_RELEASE);}
