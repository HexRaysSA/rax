#include <windows.h>
#include <cstdio>
#include <cstring>
#include <initializer_list>
using Q=LONG(NTAPI*)(ULONG,void*,ULONG,ULONG*);
using T=LONG(NTAPI*)(ULONG*,ULONG*,ULONG*);
int main(){SYSTEM_INFO si{};GetSystemInfo(&si);MEMORYSTATUSEX ms{sizeof(ms)};GlobalMemoryStatusEx(&ms);
auto m=GetModuleHandleW(L"ntdll.dll");auto q=reinterpret_cast<Q>(GetProcAddress(m,"NtQuerySystemInformation"));auto t=reinterpret_cast<T>(GetProcAddress(m,"NtQueryTimerResolution"));ULONG lo=0,hi=0,cur=0;t(&lo,&hi,&cur);alignas(16)unsigned char b[80]{};ULONG r=0;q(0,b,sizeof(void*)==4?44:64,&r);
printf("width=%zu page=%lu min=%p max=%p affinity=%llX processors=%lu granularity=%lu ram=%llu timer-min=%lu timer-max=%lu timer-current=%lu\n",sizeof(void*),si.dwPageSize,si.lpMinimumApplicationAddress,si.lpMaximumApplicationAddress,(unsigned long long)si.dwActiveProcessorMask,si.dwNumberOfProcessors,si.dwAllocationGranularity,ms.ullTotalPhys,lo,hi,cur);for(unsigned i=0;i<r;i++)printf("%02x",b[i]);putchar('\n');
auto p=static_cast<unsigned char*>(VirtualAlloc(nullptr,8192,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE));DWORD old;
for(unsigned n:{0u,1u,3u,4u,7u,8u,16u,20u,24u,28u,32u,36u,40u,41u,42u,43u}){VirtualProtect(p,8192,PAGE_READWRITE,&old);memset(p,0xa5,8192);VirtualProtect(p+4096,4096,PAGE_NOACCESS,&old);r=0xa5a5a5a5;auto s=q(0,p+4096-n,sizeof(void*)==4?44:64,&r);printf("prefix=%u status=%08lX ret=%08lX bytes=",n,s,r);for(unsigned i=0;i<n;i++)printf("%02x",p[4096-n+i]);putchar('\n');}VirtualFree(p,0,MEM_RELEASE);}
