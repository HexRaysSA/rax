#include <windows.h>
#include <psapi.h>
#include <cstdio>
#include <cstring>
#include <initializer_list>
#include <cstdint>
// Original read-only native NLS section oracle. Process-local mappings only;
// no registry writes, configuration changes, privileges or guest forwarding.
using Get=LONG(NTAPI*)(ULONG,ULONG,void*,void**,ULONG*);
using Unmap=LONG(NTAPI*)(HANDLE,void*);
using Protect=LONG(NTAPI*)(HANDLE,void**,SIZE_T*,ULONG,ULONG*);
using Free=LONG(NTAPI*)(HANDLE,void**,SIZE_T*,ULONG);
using Allocate=LONG(NTAPI*)(HANDLE,void**,ULONG_PTR,SIZE_T*,ULONG,ULONG);
static Get get;
static LONG invoke(ULONG type,ULONG data,void* context,void** out,ULONG* size,ULONG* exception){
 __try{return get(type,data,context,out,size);}__except(EXCEPTION_EXECUTE_HANDLER){*exception=GetExceptionCode();return LONG(*exception);}
}
static unsigned long hash(const unsigned char* p,size_t n){unsigned long h=2166136261u;for(size_t i=0;i<n;i++){h^=p[i];h*=16777619u;}return h;}
int main(){setvbuf(stdout,nullptr,_IONBF,0);auto n=GetModuleHandleW(L"ntdll.dll");get=reinterpret_cast<Get>(GetProcAddress(n,"NtGetNlsSectionPtr"));auto unmap=reinterpret_cast<Unmap>(GetProcAddress(n,"NtUnmapViewOfSection"));printf("pointer=%zu get=%u ACP=%u OEMCP=%u\n",sizeof(void*),unsigned(get!=nullptr),GetACP(),GetOEMCP());if(!get||!unmap)return 1;
 for(ULONG type:{11u,12u,14u})for(ULONG data:{0u,1u,2u,3u,4u,5u,6u,13u,14u,0x101u,0x102u,0x105u,0x106u,0x10du,437u,1252u,65001u,0xffffffffu}){void* out=reinterpret_cast<void*>(uintptr_t(0xa5a5a5a5));ULONG size=0xa5a5a5a5,ex=0;auto status=invoke(type,data,nullptr,&out,&size,&ex);printf("matrix type=%lu data=%lu status=%08lX exception=%08lX out=%p size=%lu",type,data,status,ex,out,size);if(status>=0&&out){MEMORY_BASIC_INFORMATION m{};VirtualQuery(out,&m,sizeof(m));printf(" region=%zu protect=%08lX memtype=%08lX",m.RegionSize,m.Protect,m.Type);if(size&&size<=m.RegionSize&&size<=(8u<<20)){auto p=static_cast<const unsigned char*>(out);printf(" hash=%08lX bytes=",hash(p,size));for(ULONG i=0;i<64&&i<size;i++)printf("%02X",p[i]);}wchar_t path[1024]{};if(GetMappedFileNameW(GetCurrentProcess(),out,path,1024))printf(" path=%ls",path);unmap(GetCurrentProcess(),out);}printf("\n");}
 auto p=static_cast<unsigned char*>(VirtualAlloc(nullptr,12288,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE));if(!p)return 2;DWORD old;
 for(unsigned role=0;role<51;role++){VirtualProtect(p,12288,PAGE_READWRITE,&old);memset(p,0xa5,12288);ULONG type=11,data=GetACP(),ex=0;void* context=nullptr;void** out=reinterpret_cast<void**>(p+64);ULONG* size=reinterpret_cast<ULONG*>(p+128);
 switch(role){case 1:size=nullptr;break;case 2:out=nullptr;break;case 3:out=reinterpret_cast<void**>(uintptr_t(1));break;case 4:size=reinterpret_cast<ULONG*>(uintptr_t(1));break;case 5:out=reinterpret_cast<void**>(p+65);break;case 6:size=reinterpret_cast<ULONG*>(p+129);break;case 7:context=reinterpret_cast<void*>(uintptr_t(1));break;case 8:out=reinterpret_cast<void**>(p+4096);VirtualProtect(p+4096,4096,PAGE_NOACCESS,&old);break;case 9:size=reinterpret_cast<ULONG*>(p+4096);VirtualProtect(p+4096,4096,PAGE_NOACCESS,&old);break;case 10:out=reinterpret_cast<void**>(p+4096);VirtualProtect(p+4096,4096,PAGE_READWRITE|PAGE_GUARD,&old);break;case 11:size=reinterpret_cast<ULONG*>(p+4096);VirtualProtect(p+4096,4096,PAGE_READWRITE|PAGE_GUARD,&old);break;case 12:context=p+4096;VirtualProtect(p+4096,4096,PAGE_NOACCESS,&old);break;case 13:context=p+4096;VirtualProtect(p+4096,4096,PAGE_READWRITE|PAGE_GUARD,&old);break;case 14:out=nullptr;size=nullptr;break;case 15:type=0;out=nullptr;size=nullptr;break;case 16:type=0;out=reinterpret_cast<void**>(uintptr_t(1));break;case 17:data=0xffffffffu;out=nullptr;size=nullptr;break;case 18:data=0xffffffffu;out=reinterpret_cast<void**>(uintptr_t(1));break;case 19:size=reinterpret_cast<ULONG*>(p+64);break;case 20:size=reinterpret_cast<ULONG*>(p+68);break;case 21:out=reinterpret_cast<void**>(p+4096-sizeof(void*));size=reinterpret_cast<ULONG*>(p+4094);VirtualProtect(p+4096,4096,PAGE_NOACCESS,&old);break;case 22:out=reinterpret_cast<void**>(p+4093);VirtualProtect(p+4096,4096,PAGE_NOACCESS,&old);break;case 23:type=10;data=0;break;case 24:type=9;data=0;break;case 25:type=12;data=0;break;case 26:type=11;data=0;break;case 27:type=11;data=65535;break;
case 28:context=p+256;memset(context,0,64);break;
case 29:context=p+256;memset(context,0,64);p[256]=1;break;
case 30:context=p+4095;VirtualProtect(p+4096,4096,PAGE_NOACCESS,&old);break;
case 31:context=p+4092;VirtualProtect(p+4096,4096,PAGE_NOACCESS,&old);break;
case 32:context=p+4088;VirtualProtect(p+4096,4096,PAGE_NOACCESS,&old);break;
case 33:context=p+4080;VirtualProtect(p+4096,4096,PAGE_NOACCESS,&old);break;
case 34:type=0;context=reinterpret_cast<void*>(uintptr_t(1));break;
case 35:type=0;out=nullptr;context=reinterpret_cast<void*>(uintptr_t(1));break;
case 36:type=0;size=reinterpret_cast<ULONG*>(uintptr_t(1));break;
case 37:out=nullptr;size=reinterpret_cast<ULONG*>(uintptr_t(1));break;
case 38:out=reinterpret_cast<void**>(p+4096);size=reinterpret_cast<ULONG*>(p+8192);VirtualProtect(p+4096,8192,PAGE_READWRITE|PAGE_GUARD,&old);break;
case 39:out=reinterpret_cast<void**>(p+4096);context=p+8192;VirtualProtect(p+4096,8192,PAGE_READWRITE|PAGE_GUARD,&old);break;
case 40:context=p+4096;size=reinterpret_cast<ULONG*>(p+8192);VirtualProtect(p+4096,8192,PAGE_READWRITE|PAGE_GUARD,&old);break;
case 41:type=0;size=reinterpret_cast<ULONG*>(p+4096);VirtualProtect(p+4096,4096,PAGE_READWRITE|PAGE_GUARD,&old);break;
case 42:type=0;out=reinterpret_cast<void**>(p+4096);VirtualProtect(p+4096,4096,PAGE_READWRITE|PAGE_GUARD,&old);break;
case 43:type=0;context=p+4096;VirtualProtect(p+4096,4096,PAGE_READWRITE|PAGE_GUARD,&old);break;
case 44:type=0;size=nullptr;break;
case 45:out=nullptr;context=p+256;memset(context,0,64);break;
case 46:type=0;context=p+256;memset(context,0,64);break;
case 47:data=0xffffffffu;context=p+256;memset(context,0,64);break;
case 48:type=0;size=reinterpret_cast<ULONG*>(p+4096);VirtualProtect(p+4096,4096,PAGE_NOACCESS,&old);break;
case 49:data=0xffffffffu;size=reinterpret_cast<ULONG*>(p+4096);VirtualProtect(p+4096,4096,PAGE_READWRITE|PAGE_GUARD,&old);break;
case 50:context=reinterpret_cast<void*>(uintptr_t(1));size=reinterpret_cast<ULONG*>(uintptr_t(1));break;}
 auto status=invoke(type,data,context,out,size,&ex);MEMORY_BASIC_INFORMATION m{};VirtualQuery(p+4096,&m,sizeof(m));auto protect=m.Protect;MEMORY_BASIC_INFORMATION m2{};VirtualQuery(p+8192,&m2,sizeof(m2));printf("second_guard=%u ",unsigned((m2.Protect&PAGE_GUARD)!=0));printf("fault role=%u type=%lu data=%lu status=%08lX exception=%08lX guard=%u bytes=",role,type,data,status,ex,unsigned((protect&PAGE_GUARD)!=0));for(unsigned i=64;i<144;i++)printf("%02X",p[i]);printf("\n");if(status>=0&&out&&reinterpret_cast<uintptr_t>(out)>=reinterpret_cast<uintptr_t>(p)&&reinterpret_cast<uintptr_t>(out)+sizeof(void*)<=reinterpret_cast<uintptr_t>(p)+4096){void* mapped=nullptr;memcpy(&mapped,out,sizeof(mapped));if(mapped&&reinterpret_cast<uintptr_t>(mapped)!=uintptr_t(0xa5a5a5a5))unmap(GetCurrentProcess(),mapped);}
 }VirtualFree(p,0,MEM_RELEASE);
for(unsigned role=0;role<12;role++){void* a=nullptr;void* b=nullptr;ULONG as=0,bs=0,ex=0;auto ga=invoke(11,GetACP(),nullptr,&a,&as,&ex);auto gb=invoke(11,GetACP(),nullptr,&b,&bs,&ex);HANDLE process=GetCurrentProcess();void* address=a;if(role==1)address=static_cast<char*>(a)+1;if(role==2)address=static_cast<char*>(a)+as-1;if(role==3)address=nullptr;if(role==4)address=reinterpret_cast<void*>(uintptr_t(1));if(role==5)process=nullptr;if(role==6)process=reinterpret_cast<HANDLE>(intptr_t(-2));if(role==7)process=reinterpret_cast<HANDLE>(uintptr_t(0x1234));if(role==8){process=nullptr;address=nullptr;}if(role==9){process=reinterpret_cast<HANDLE>(intptr_t(-2));address=nullptr;}if(role==10){process=nullptr;address=reinterpret_cast<void*>(uintptr_t(1));}if(role==11)address=static_cast<char*>(a)+as;auto u=unmap(process,address);auto again=unmap(GetCurrentProcess(),a);auto cleanup=unmap(GetCurrentProcess(),b);printf("unmap role=%u ga=%08lX gb=%08lX distinct=%u first=%08lX again=%08lX cleanup=%08lX size=%lu\n",role,ga,gb,unsigned(a!=b),u,again,cleanup,as);}for(DWORD desired:{PAGE_READONLY,PAGE_READWRITE,PAGE_WRITECOPY,PAGE_EXECUTE,PAGE_EXECUTE_READ,PAGE_EXECUTE_READWRITE,PAGE_EXECUTE_WRITECOPY,PAGE_READONLY|PAGE_GUARD}){void* a=nullptr;ULONG size=0,ex=0;auto status=invoke(11,GetACP(),nullptr,&a,&size,&ex);DWORD old=0;SetLastError(0);auto ok=VirtualProtect(a,size,desired,&old);auto error=GetLastError();printf("protect desired=%08lX map=%08lX ok=%u error=%lu old=%08lX\n",desired,status,unsigned(ok),error,old);unmap(GetCurrentProcess(),a);}
auto protect=reinterpret_cast<Protect>(GetProcAddress(n,"NtProtectVirtualMemory"));auto free=reinterpret_cast<Free>(GetProcAddress(n,"NtFreeVirtualMemory"));auto allocate=reinterpret_cast<Allocate>(GetProcAddress(n,"NtAllocateVirtualMemory"));
for(ULONG desired:{PAGE_NOACCESS,PAGE_READONLY,PAGE_READWRITE,PAGE_WRITECOPY,PAGE_EXECUTE,PAGE_EXECUTE_READ,PAGE_EXECUTE_READWRITE,PAGE_EXECUTE_WRITECOPY,PAGE_READONLY|PAGE_GUARD}){void* a=nullptr;ULONG size=0,ex=0;invoke(11,GetACP(),nullptr,&a,&size,&ex);void* address=a;SIZE_T length=size;ULONG old=0xa5a5a5a5;auto s=protect(GetCurrentProcess(),&address,&length,desired,&old);printf("ntprotect desired=%08lX status=%08lX old=%08lX len=%zu\n",desired,s,old,length);unmap(GetCurrentProcess(),a);}
for(ULONG kind:{MEM_RELEASE,MEM_DECOMMIT}){void* a=nullptr;ULONG size=0,ex=0;invoke(11,GetACP(),nullptr,&a,&size,&ex);void* address=a;SIZE_T length=kind==MEM_RELEASE?0:size;auto s=free(GetCurrentProcess(),&address,&length,kind);printf("ntfree kind=%08lX status=%08lX len=%zu\n",kind,s,length);unmap(GetCurrentProcess(),a);}
for(ULONG desired:{PAGE_READONLY,PAGE_READWRITE}){void* a=nullptr;ULONG size=0,ex=0;invoke(11,GetACP(),nullptr,&a,&size,&ex);void* address=a;SIZE_T length=size;printf("ntcommit before=%08lX\n",desired);ULONG captured=desired;auto s=allocate(GetCurrentProcess(),&address,0,&length,MEM_COMMIT,desired);printf("ntcommit captured=%08lX\n",captured);printf("ntcommit desired=%08lX status=%08lX len=%zu\n",desired,s,length);unmap(GetCurrentProcess(),a);}return 0;}
