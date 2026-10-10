#include <windows.h>
#include <cstdio>
#include <initializer_list>
using Allocate=LONG(NTAPI*)(HANDLE,void**,SIZE_T*,ULONG,ULONG,MEM_EXTENDED_PARAMETER*,ULONG);
int main(){
 auto allocate=reinterpret_cast<Allocate>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtAllocateVirtualMemoryEx"));if(!allocate)return 1;
 HANDLE restricted=OpenProcess(PROCESS_QUERY_INFORMATION,FALSE,GetCurrentProcessId());if(!restricted)return 2;
 HANDLE handles[]={reinterpret_cast<HANDLE>(LONG_PTR(-1)),nullptr,reinterpret_cast<HANDLE>(LONG_PTR(-2)),restricted};
 for(unsigned kind:{2u,5u})for(unsigned h=0;h<4;++h)for(unsigned fault=0;fault<3;++fault){
  alignas(16) MEM_ADDRESS_REQUIREMENTS req{};alignas(16) MEM_EXTENDED_PARAMETER records[2]{};
  records[0].Type=kind;records[0].ULong64=kind==2?255:1;records[1].Type=MemExtendedParameterAddressRequirements;records[1].Pointer=fault==1?nullptr:&req;
  if(fault==2)req.Alignment=4096;
  alignas(16) void* base=nullptr;alignas(16) SIZE_T size=4096;
  const LONG status=allocate(handles[h],&base,&size,MEM_RESERVE,PAGE_READWRITE,records,2);const BOOL freed=status>=0?VirtualFree(base,0,MEM_RELEASE):TRUE;
  printf("width=%zu kind=%u handle=%u fault=%u status=%08lX base=%p size=%llX freed=%u\n",sizeof(void*),kind,h,fault,static_cast<ULONG>(status),base,static_cast<unsigned long long>(size),!!freed);
  if(!freed){CloseHandle(restricted);return 3;}
 }
 CloseHandle(restricted);return 0;
}
