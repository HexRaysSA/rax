#include <windows.h>
#include <cstdio>
#include <cstring>
using Allocate=LONG(NTAPI*)(HANDLE,void**,SIZE_T*,ULONG,ULONG,MEM_EXTENDED_PARAMETER*,ULONG);
static LONG call(Allocate allocate,void** base,SIZE_T* size,MEM_EXTENDED_PARAMETER* parameters,ULONG count,DWORD* exception){
 LONG status=0;__try{status=allocate(reinterpret_cast<HANDLE>(LONG_PTR(-1)),base,size,MEM_RESERVE,PAGE_READWRITE,parameters,count);}__except(EXCEPTION_EXECUTE_HANDLER){*exception=GetExceptionCode();}return status;
}
int main(){
 auto allocate=reinterpret_cast<Allocate>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtAllocateVirtualMemoryEx"));if(!allocate)return 1;
 const unsigned shifts[]={0,1,4,8};
 for(unsigned mode=18;mode<33;++mode)for(auto shift:shifts){
  alignas(16) MEM_ADDRESS_REQUIREMENTS req{};alignas(16) MEM_EXTENDED_PARAMETER records[2]{};ULONG count=2;
  auto set=[&](unsigned index,unsigned kind){records[index].Type=kind;if(kind==1)records[index].Pointer=&req;};
  switch(mode){
   case 0:set(0,1);set(1,2);break;case 1:set(0,2);set(1,1);break;
   case 2:set(0,1);set(1,5);break;case 3:set(0,5);set(1,1);break;
   case 4:set(0,2);set(1,5);break;case 5:set(0,1);set(1,1);break;
   case 6:set(0,255);set(1,1);break;case 7:set(0,1);set(1,255);break;
   case 8:set(0,2);records[0].ULong64=255;set(1,1);break;
   case 9:set(0,1);records[0].Pointer=nullptr;set(1,2);break;
   case 10:set(0,2);set(1,1);records[1].Pointer=nullptr;break;
   case 11:set(0,1);records[0].Pointer=reinterpret_cast<void*>(1);set(1,2);break;
   case 12:set(0,255);count=1;break;case 13:set(0,3);count=1;break;
   case 14:set(0,1);records[0].Reserved=1;count=1;break;
   case 15:set(0,1);records[0].Reserved=1;records[0].Pointer=nullptr;count=1;break;
   case 16:set(0,255);set(1,1);records[1].Pointer=nullptr;break;
   case 17:set(0,1);records[0].Pointer=nullptr;set(1,255);break;
   case 18:set(0,4);count=1;break;case 19:set(0,6);count=1;break;
   case 20:set(0,0);count=1;break;case 21:set(0,7);count=1;break;
   case 22:set(0,3);records[0].Reserved=1;count=1;break;
   case 23:set(0,1);records[0].Reserved=1;count=1;break;
   case 24:set(0,1);set(1,1);records[1].Pointer=nullptr;break;
   case 25:set(0,1);records[0].Pointer=nullptr;set(1,1);break;
   case 26:set(0,2);records[0].ULong64=255;set(1,1);records[1].Pointer=nullptr;break;
   case 27:set(0,2);set(1,1);records[1].Reserved=1;records[1].Pointer=nullptr;break;
   case 28:set(0,5);records[0].ULong64=1;set(1,1);records[1].Pointer=nullptr;break;
   case 29:set(0,0);set(1,1);records[1].Pointer=nullptr;break;
   case 30:set(0,3);records[0].ULong64=1;set(1,1);records[1].Pointer=nullptr;break;
   case 31:set(0,4);records[0].ULong64=1;set(1,1);records[1].Pointer=nullptr;break;
   case 32:set(0,6);records[0].ULong64=1;set(1,1);records[1].Pointer=nullptr;break;

  }
  alignas(16) BYTE bytes[96]{};memcpy(bytes+shift,records,sizeof(records));auto parameter=reinterpret_cast<MEM_EXTENDED_PARAMETER*>(bytes+shift);
  alignas(16) void* base=nullptr;alignas(16) SIZE_T size=4096;DWORD exception=0;
  const LONG status=call(allocate,&base,&size,parameter,count,&exception);
  const BOOL freed=status>=0&&!exception?VirtualFree(base,0,MEM_RELEASE):TRUE;
  printf("width=%zu mode=%u shift=%u count=%lu parameter=%p status=%08lX exception=%08lX base=%p size=%llX freed=%u\n",sizeof(void*),mode,shift,count,parameter,static_cast<ULONG>(status),exception,base,static_cast<unsigned long long>(size),!!freed);
  if(!freed)return 2;
 }
 return 0;
}
