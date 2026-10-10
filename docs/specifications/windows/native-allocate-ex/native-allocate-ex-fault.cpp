#include <windows.h>
#include <cstdio>
#include <cstring>
using Allocate=LONG(NTAPI*)(HANDLE,void**,SIZE_T*,ULONG,ULONG,MEM_EXTENDED_PARAMETER*,ULONG);
using Free=LONG(NTAPI*)(HANDLE,void**,SIZE_T*,ULONG);
static LONG call(Allocate fn,HANDLE handle,void** base,SIZE_T* size,ULONG flags,ULONG protect,MEM_EXTENDED_PARAMETER* params,ULONG count,DWORD* exception){
 LONG status=0; __try {status=fn(handle,base,size,flags,protect,params,count);} __except(EXCEPTION_EXECUTE_HANDLER){*exception=GetExceptionCode();} return status;
}
int main(){
 setvbuf(stdout,nullptr,_IONBF,0);auto dll=GetModuleHandleW(L"ntdll.dll");auto fn=reinterpret_cast<Allocate>(GetProcAddress(dll,"NtAllocateVirtualMemoryEx"));auto release=reinterpret_cast<Free>(GetProcAddress(dll,"NtFreeVirtualMemory"));if(!fn||!release)return 1;
 const char* names[]={"base-null","size-null","base-unaligned","size-unaligned","base-unmapped","size-unmapped","base-readonly","size-readonly","base-guard","size-guard","parameters-guard","requirements-guard","handle-null","handle-thread","handle-invalid","bad-flags-base-null","bad-flags-parameters-null","bad-protect-base-null","bad-count-base-null","bad-parameters-base-null","bad-parameters-size-null","unaligned-parameters-base-null","unaligned-requirements-base-null","unknown-type-base-null","duplicate-numa","duplicate-attributes","numa-unspecified","attributes-unknown","attributes-ec-code","requirements-high-limit","requirements-low-above-limit","requirements-size-overflow","parameters-cross-inaccessible","requirements-cross-inaccessible"};
 for(unsigned mode=0;mode<sizeof(names)/sizeof(names[0]);++mode){
  auto page=static_cast<unsigned char*>(VirtualAlloc(nullptr,8192,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE));if(!page)return 2;
  void* base=nullptr;SIZE_T size=4096;void** bp=&base;SIZE_T* sp=&size;ULONG flags=MEM_RESERVE,protect=PAGE_READWRITE,count=1;HANDLE handle=reinterpret_cast<HANDLE>(LONG_PTR(-1));
  MEM_ADDRESS_REQUIREMENTS req{};MEM_EXTENDED_PARAMETER params[8]{};params[0].Type=MemExtendedParameterAddressRequirements;params[0].Pointer=&req;auto input=params;DWORD old=0;
  switch(mode){
   case 0:bp=nullptr;break;case 1:sp=nullptr;break;
   case 2:memcpy(page+1,&base,sizeof(base));bp=reinterpret_cast<void**>(page+1);break;
   case 3:memcpy(page+1,&size,sizeof(size));sp=reinterpret_cast<SIZE_T*>(page+1);break;
   case 4:bp=reinterpret_cast<void**>(0xdead0000);break;case 5:sp=reinterpret_cast<SIZE_T*>(0xdead0000);break;
   case 6:memcpy(page,&base,sizeof(base));VirtualProtect(page,4096,PAGE_READONLY,&old);bp=reinterpret_cast<void**>(page);break;
   case 7:memcpy(page,&size,sizeof(size));VirtualProtect(page,4096,PAGE_READONLY,&old);sp=reinterpret_cast<SIZE_T*>(page);break;
   case 8:memcpy(page,&base,sizeof(base));VirtualProtect(page,4096,PAGE_READWRITE|PAGE_GUARD,&old);bp=reinterpret_cast<void**>(page);break;
   case 9:memcpy(page,&size,sizeof(size));VirtualProtect(page,4096,PAGE_READWRITE|PAGE_GUARD,&old);sp=reinterpret_cast<SIZE_T*>(page);break;
   case 10:memcpy(page,params,sizeof(params[0]));VirtualProtect(page,4096,PAGE_READWRITE|PAGE_GUARD,&old);input=reinterpret_cast<MEM_EXTENDED_PARAMETER*>(page);break;
   case 11:memcpy(page,&req,sizeof(req));VirtualProtect(page,4096,PAGE_READWRITE|PAGE_GUARD,&old);params[0].Pointer=page;break;
   case 12:handle=nullptr;break;case 13:handle=reinterpret_cast<HANDLE>(LONG_PTR(-2));break;case 14:handle=reinterpret_cast<HANDLE>(0x1234);break;
   case 15:flags=0;bp=nullptr;break;case 16:flags=0;input=nullptr;break;case 17:protect=0;bp=nullptr;break;
   case 18:bp=nullptr;count=7;break;case 19:bp=nullptr;input=reinterpret_cast<MEM_EXTENDED_PARAMETER*>(1);break;case 20:sp=nullptr;input=reinterpret_cast<MEM_EXTENDED_PARAMETER*>(1);break;
   case 21:bp=nullptr;memcpy(page+1,params,sizeof(params[0]));input=reinterpret_cast<MEM_EXTENDED_PARAMETER*>(page+1);break;
   case 22:bp=nullptr;memcpy(page+1,&req,sizeof(req));params[0].Pointer=page+1;break;
   case 23:bp=nullptr;params[0].Type=255;break;
   case 24:count=2;params[0].Type=MemExtendedParameterNumaNode;params[0].ULong64=0;params[1]=params[0];break;
   case 25:count=2;params[0].Type=MemExtendedParameterAttributeFlags;params[0].ULong64=0;params[1]=params[0];break;
   case 26:params[0].Type=MemExtendedParameterNumaNode;params[0].ULong64=0xffffffff;break;
   case 27:params[0].Type=MemExtendedParameterAttributeFlags;params[0].ULong64=1ull<<63;break;
   case 28:params[0].Type=MemExtendedParameterAttributeFlags;params[0].ULong64=0x40;break;
   case 29:req.HighestEndingAddress=reinterpret_cast<void*>(sizeof(void*)==4 ? 0x7ffeffffull : 0x7ffffffeffffull);break;
   case 30:req.LowestStartingAddress=reinterpret_cast<void*>(sizeof(void*)==4 ? 0x80000000ull : 0x800000000000ull);break;
   case 31:size=~SIZE_T(0);break;
   case 32:memcpy(page+4096-8,params,sizeof(params[0]));VirtualProtect(page+4096,4096,PAGE_NOACCESS,&old);input=reinterpret_cast<MEM_EXTENDED_PARAMETER*>(page+4096-8);break;
   case 33:memcpy(page+4096-sizeof(void*),&req,sizeof(req));VirtualProtect(page+4096,4096,PAGE_NOACCESS,&old);params[0].Pointer=page+4096-sizeof(void*);break;
  }
  DWORD exception=0;LONG status=call(fn,handle,bp,sp,flags,protect,input,count,&exception);MEMORY_BASIC_INFORMATION info{};VirtualQuery(page,&info,sizeof(info));
  printf("case=%s width=%zu status=%08lX exception=%08lX base=%llX size=%llX page-protect=%08lX",names[mode],sizeof(void*),status,exception,static_cast<unsigned long long>(reinterpret_cast<ULONG_PTR>(base)),static_cast<unsigned long long>(size),info.Protect);
  void* allocated=base;if(status>=0&&!exception&&bp!=&base)memcpy(&allocated,bp,sizeof(allocated));
  if(allocated){SIZE_T zero=0;LONG freed=release(reinterpret_cast<HANDLE>(LONG_PTR(-1)),&allocated,&zero,MEM_RELEASE);printf(" freed=%08lX",freed);if(freed<0)return 3;}
  putchar('\n');VirtualFree(page,0,MEM_RELEASE);
 }
 for(unsigned count=0;count<=16;++count){
  MEM_EXTENDED_PARAMETER params[32]{};void* base=nullptr;SIZE_T size=4096;DWORD exception=0;LONG status=call(fn,reinterpret_cast<HANDLE>(LONG_PTR(-1)),&base,&size,MEM_RESERVE,PAGE_READWRITE,params,count,&exception);
  printf("case=valid-array-count width=%zu count=%u status=%08lX exception=%08lX base=%llX size=%llX\n",sizeof(void*),count,status,exception,static_cast<unsigned long long>(reinterpret_cast<ULONG_PTR>(base)),static_cast<unsigned long long>(size));
  if(status>=0&&!exception){SIZE_T zero=0;if(release(reinterpret_cast<HANDLE>(LONG_PTR(-1)),&base,&zero,MEM_RELEASE)<0)return 4;}
 }
 return 0;
}
