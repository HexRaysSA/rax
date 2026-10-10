#include <windows.h>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <initializer_list>
// Original process-local query/write-order oracle; no image mutation.
using Query=LONG(NTAPI*)(HANDLE,const void*,ULONG,void*,SIZE_T,SIZE_T*);
static Query query;
static LONG invoke(HANDLE h,const void* a,ULONG k,void* o,SIZE_T n,SIZE_T* r,ULONG* e){__try{return query(h,a,k,o,n,r);}__except(EXCEPTION_EXECUTE_HANDLER){*e=GetExceptionCode();return LONG(*e);}}
int main(){setvbuf(stdout,nullptr,_IONBF,0);auto image=GetModuleHandleW(nullptr);query=reinterpret_cast<Query>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtQueryVirtualMemory"));auto p=static_cast<unsigned char*>(VirtualAlloc(nullptr,16384,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE));if(!p||!query)return 1;DWORD old;printf("pointer=%zu main=%p\n",sizeof(void*),image);
for(ULONG kind:{0u,6u})for(unsigned role=0;role<12;role++){VirtualProtect(p,16384,PAGE_READWRITE,&old);memset(p,0xa5,16384);void* out=p+4096;auto ret=reinterpret_cast<SIZE_T*>(p+4160);HANDLE h=GetCurrentProcess();const void* address=image;SIZE_T len=64;
switch(role){case 1:ret=reinterpret_cast<SIZE_T*>(out);break;case 2:ret=reinterpret_cast<SIZE_T*>(p+4092);break;case 3:ret=reinterpret_cast<SIZE_T*>(p+8192);break;case 4:ret=nullptr;break;case 5:h=nullptr;break;case 6:address=nullptr;break;case 7:len=0;break;case 8:out=p+4096+3;break;case 9:out=p+4088;break;case 10:out=p+4096;ret=reinterpret_cast<SIZE_T*>(p+12288);break;case 11:out=p+4096;ret=reinterpret_cast<SIZE_T*>(p+4224);break;}
VirtualProtect(p+4096,4096,PAGE_READWRITE|PAGE_GUARD,&old);if(role==3)VirtualProtect(p+8192,4096,PAGE_READWRITE|PAGE_GUARD,&old);ULONG exception=0;LONG status=invoke(h,address,kind,out,len,ret,&exception);MEMORY_BASIC_INFORMATION a{},b{};VirtualQuery(p+4096,&a,sizeof(a));VirtualQuery(p+8192,&b,sizeof(b));printf("alias role=%u class=%lu status=%08lX exception=%08lX guards=%u%u output=",role,kind,status,exception,unsigned((a.Protect&PAGE_GUARD)!=0),unsigned((b.Protect&PAGE_GUARD)!=0));
// Report state before removing any remaining guard for nonintrusive byte capture.
VirtualProtect(p,16384,PAGE_READWRITE,&old);for(unsigned i=0;i<64;i++)printf("%02X",static_cast<unsigned char*>(out)[i]);printf(" returned=");if(ret){for(unsigned i=0;i<16;i++)printf("%02X",reinterpret_cast<unsigned char*>(ret)[i]);}printf("\n");}
VirtualFree(p,0,MEM_RELEASE);return 0;}
