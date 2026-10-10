#include <windows.h>
#include <cstdio>
#include <cstdint>
using Allocate=LONG(NTAPI*)(HANDLE,void**,SIZE_T*,ULONG,ULONG,MEM_EXTENDED_PARAMETER*,ULONG);
int main(){
 auto allocate=reinterpret_cast<Allocate>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtAllocateVirtualMemoryEx"));if(!allocate)return 1;
 for(unsigned mode=0;mode<6;++mode){
  alignas(16) MEM_ADDRESS_REQUIREMENTS req{};alignas(16) MEM_EXTENDED_PARAMETER record{};record.Type=MemExtendedParameterAddressRequirements;
  const auto pointer=static_cast<ULONGLONG>(reinterpret_cast<uintptr_t>(&req));const auto low=pointer&0xFFFFFFFFULL;
  switch(mode){case 0:record.ULong64=pointer;break;case 1:record.ULong64=low|(((pointer>>32)+1)<<32);break;case 2:record.ULong64=low|0xFFFFFFFF00000000ULL;break;case 3:record.ULong64=0x100000000ULL;break;case 4:record.ULong64=low;break;case 5:record.ULong64=low|0xA5A5A5A500000000ULL;break;}
  alignas(16) void* base=nullptr;alignas(16) SIZE_T size=4096;
  LONG status=allocate(GetCurrentProcess(),&base,&size,MEM_RESERVE,PAGE_READWRITE,&record,1);
  BOOL freed=status>=0?VirtualFree(base,0,MEM_RELEASE):TRUE;
  printf("width=%zu mode=%u pointer=%016llX payload=%016llX status=%08lX base=%p size=%llX freed=%u\n",sizeof(void*),mode,pointer,record.ULong64,static_cast<ULONG>(status),base,static_cast<ULONGLONG>(size),!!freed);if(!freed)return 2;
 }
 return 0;
}
