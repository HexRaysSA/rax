#include <windows.h>
#include <cstdio>
#include <cstring>
using Allocate=LONG(NTAPI*)(HANDLE,void**,SIZE_T*,ULONG,ULONG,MEM_EXTENDED_PARAMETER*,ULONG);
using Free=LONG(NTAPI*)(HANDLE,void**,SIZE_T*,ULONG);
int main(){setvbuf(stdout,nullptr,_IONBF,0);auto dll=GetModuleHandleW(L"ntdll.dll");auto fn=reinterpret_cast<Allocate>(GetProcAddress(dll,"NtAllocateVirtualMemoryEx"));auto freefn=reinterpret_cast<Free>(GetProcAddress(dll,"NtFreeVirtualMemory"));if(!fn||!freefn)return 1;
 const char* names[]={"count-seven-inaccessible-aligned","count-six-inaccessible-aligned","count-seven-accessible-prefix","unknown-type-before-inaccessible-second","requirements-before-inaccessible-second","invalid-protect-range-invalid","invalid-flags-range-invalid","unaligned-array-invalid-flags","invalid-handle-unaligned-array","invalid-handle-invalid-range","base-null-size-guard","base-guard-size-null","size-readonly-invalid-type","base-readonly-invalid-type","x86-pointer-padding","range-no-aligned-fit","large-alignment","attribute-nonpaged","partition-null","user-physical-null","image-machine-zero"};
 for(unsigned mode=0;mode<sizeof(names)/sizeof(names[0]);++mode){
 auto page=static_cast<unsigned char*>(VirtualAlloc(nullptr,8192,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE));if(!page)return 2;DWORD old=0;void* base=nullptr;SIZE_T size=4096;void** bp=&base;SIZE_T* sp=&size;ULONG flags=MEM_RESERVE,protect=PAGE_READWRITE,count=1;HANDLE handle=reinterpret_cast<HANDLE>(LONG_PTR(-1));MEM_ADDRESS_REQUIREMENTS req{};alignas(16)MEM_EXTENDED_PARAMETER params[8]{};params[0].Type=1;params[0].Pointer=&req;auto input=params;
 switch(mode){
 case 0:count=7;input=reinterpret_cast<MEM_EXTENDED_PARAMETER*>(0xdead0000);break;
 case 1:count=6;input=reinterpret_cast<MEM_EXTENDED_PARAMETER*>(0xdead0000);break;
 case 2:count=7;input=reinterpret_cast<MEM_EXTENDED_PARAMETER*>(page+4096-16);memcpy(input,params,16);VirtualProtect(page+4096,4096,PAGE_NOACCESS,&old);break;
 case 3:count=2;params[0].Type=255;input=reinterpret_cast<MEM_EXTENDED_PARAMETER*>(page+4096-16);memcpy(input,params,16);VirtualProtect(page+4096,4096,PAGE_NOACCESS,&old);break;
 case 4:count=2;params[0].Pointer=reinterpret_cast<void*>(1);input=reinterpret_cast<MEM_EXTENDED_PARAMETER*>(page+4096-16);memcpy(input,params,16);VirtualProtect(page+4096,4096,PAGE_NOACCESS,&old);break;
 case 5:protect=0;req.LowestStartingAddress=reinterpret_cast<void*>(0x2000000);req.HighestEndingAddress=reinterpret_cast<void*>(0x1ffffff);break;
 case 6:flags=0;req.Alignment=4096;break;
 case 7:flags=0;input=reinterpret_cast<MEM_EXTENDED_PARAMETER*>(page+1);memcpy(input,params,16);break;
 case 8:handle=nullptr;input=reinterpret_cast<MEM_EXTENDED_PARAMETER*>(page+1);memcpy(input,params,16);break;
 case 9:handle=nullptr;req.Alignment=4096;break;
 case 10:bp=nullptr;memcpy(page,&size,sizeof(size));sp=reinterpret_cast<SIZE_T*>(page);VirtualProtect(page,4096,PAGE_READWRITE|PAGE_GUARD,&old);break;
 case 11:sp=nullptr;memcpy(page,&base,sizeof(base));bp=reinterpret_cast<void**>(page);VirtualProtect(page,4096,PAGE_READWRITE|PAGE_GUARD,&old);break;
 case 12:params[0].Type=255;memcpy(page,&size,sizeof(size));sp=reinterpret_cast<SIZE_T*>(page);VirtualProtect(page,4096,PAGE_READONLY,&old);break;
 case 13:params[0].Type=255;memcpy(page,&base,sizeof(base));bp=reinterpret_cast<void**>(page);VirtualProtect(page,4096,PAGE_READONLY,&old);break;
 case 14:if(sizeof(void*)==4)params[0].ULong64|=0xabcdef0100000000ull;break;
 case 15:req.LowestStartingAddress=reinterpret_cast<void*>(0x10000);req.HighestEndingAddress=reinterpret_cast<void*>(0x1ffff);req.Alignment=0x20000;break;
 case 16:req.Alignment=sizeof(void*)==4?0x80000000ull:0x800000000000ull;break;
 case 17:params[0].Type=5;params[0].ULong64=2;break;
 case 18:params[0].Type=3;params[0].ULong64=0;break;
 case 19:params[0].Type=4;params[0].ULong64=0;break;
 case 20:params[0].Type=6;params[0].ULong64=0;break;
 }
 LONG status=fn(handle,bp,sp,flags,protect,input,count);MEMORY_BASIC_INFORMATION info{};VirtualQuery(page,&info,sizeof(info));printf("case=%s width=%zu status=%08lX base=%llX size=%llX page-protect=%08lX",names[mode],sizeof(void*),status,static_cast<unsigned long long>(reinterpret_cast<ULONG_PTR>(base)),static_cast<unsigned long long>(size),info.Protect);
 void* allocated=base;if(status>=0&&bp!=&base)memcpy(&allocated,bp,sizeof(allocated));if(allocated){SIZE_T zero=0;LONG freed=freefn(reinterpret_cast<HANDLE>(LONG_PTR(-1)),&allocated,&zero,MEM_RELEASE);printf(" freed=%08lX",freed);if(freed<0)return 3;}putchar('\n');VirtualFree(page,0,MEM_RELEASE);
 }return 0;}
