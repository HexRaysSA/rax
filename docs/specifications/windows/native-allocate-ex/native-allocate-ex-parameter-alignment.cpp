#include <windows.h>
#include <cstdio>
#include <cstring>
using Allocate=LONG(NTAPI*)(HANDLE,void**,SIZE_T*,ULONG,ULONG,MEM_EXTENDED_PARAMETER*,ULONG);
int main(){
 auto allocate=reinterpret_cast<Allocate>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtAllocateVirtualMemoryEx"));if(!allocate)return 1;
 const unsigned kinds[]={1,2,5};const unsigned shifts[]={0,1,4,8};
 for(auto kind:kinds)for(auto shift:shifts){
  alignas(16) MEM_ADDRESS_REQUIREMENTS req{};alignas(16) MEM_EXTENDED_PARAMETER record{};record.Type=kind;if(kind==1)record.Pointer=&req;
  alignas(16) BYTE bytes[64]{};memcpy(bytes+shift,&record,sizeof(record));auto parameter=reinterpret_cast<MEM_EXTENDED_PARAMETER*>(bytes+shift);
  alignas(16) void* base=nullptr;alignas(16) SIZE_T size=4096;
  const LONG status=allocate(reinterpret_cast<HANDLE>(LONG_PTR(-1)),&base,&size,MEM_RESERVE,PAGE_READWRITE,parameter,1);
  const BOOL freed=status>=0?VirtualFree(base,0,MEM_RELEASE):TRUE;
  printf("width=%zu kind=%u shift=%u parameter=%p status=%08lX base=%p size=%llX freed=%u\n",sizeof(void*),kind,shift,parameter,static_cast<ULONG>(status),base,static_cast<unsigned long long>(size),!!freed);
  if(!freed)return 2;
 }
 return 0;
}
