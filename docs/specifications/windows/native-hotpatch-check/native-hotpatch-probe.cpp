#include <windows.h>
#include <cstdio>
#include <cstring>
#include <initializer_list>
// Only private query class 9 (CheckEnabled) is invoked. No patch load, unload,
// apply, section creation or system mutation operation is issued.
using Query=LONG(NTAPI*)(ULONG,void*,ULONG,ULONG*);
int main(){
 setvbuf(stdout,nullptr,_IONBF,0);
 auto query=reinterpret_cast<Query>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtManageHotPatch"));
 printf("pointer=%zu exported=%u\n",sizeof(void*),unsigned(query!=nullptr));if(!query)return 0;
 auto p=static_cast<unsigned char*>(VirtualAlloc(nullptr,8192,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE));if(!p)return 1;DWORD old;
 for(ULONG version:{0u,1u,2u,0xFFFFFFFFu})for(ULONG flags:{0u,1u,2u,4u,8u,0xFFFFFFFFu})for(ULONG len:{0u,1u,4u,7u,8u,9u,12u,16u}){
  memset(p,0xA5,8192);memcpy(p,&version,4);memcpy(p+4,&flags,4);ULONG ret=0xA5A5A5A5;
  auto s=query(9,p,len,&ret);printf("pointer=%zu version=%08lX flags=%08lX length=%lu status=%08lX returned=%08lX bytes=",sizeof(void*),version,flags,len,s,ret);for(unsigned i=0;i<16;++i)printf("%02X",p[i]);printf("\n");
 }
 for(unsigned role=0;role<16;++role){
  VirtualProtect(p,8192,PAGE_READWRITE,&old);memset(p,0xA5,8192);memset(p,0,8);auto output=static_cast<void*>(p);auto ret=reinterpret_cast<ULONG*>(p+4096);ULONG len=8;
  switch(role){case 0:output=nullptr;break;case 1:output=p+1;break;case 2:ret=nullptr;break;case 3:ret=reinterpret_cast<ULONG*>(p+4097);break;case 4:ret=reinterpret_cast<ULONG*>(1);break;case 5:VirtualProtect(p,4096,PAGE_READONLY,&old);break;case 6:VirtualProtect(p,4096,PAGE_READWRITE|PAGE_GUARD,&old);break;case 7:VirtualProtect(p+4096,4096,PAGE_READWRITE|PAGE_GUARD,&old);break;case 8:VirtualProtect(p,4096,PAGE_NOACCESS,&old);len=7;break;case 9:VirtualProtect(p,4096,PAGE_READWRITE|PAGE_GUARD,&old);len=7;break;case 10:ret=reinterpret_cast<ULONG*>(p);break;case 11:output=nullptr;ret=reinterpret_cast<ULONG*>(1);break;case 12:output=p+4088;memset(output,0,8);len=16;VirtualProtect(p+4096,4096,PAGE_NOACCESS,&old);ret=nullptr;break;case 13:output=p+4088;memset(output,0,8);len=8;VirtualProtect(p+4096,4096,PAGE_NOACCESS,&old);ret=nullptr;break;case 14:VirtualProtect(p+4096,4096,PAGE_READONLY,&old);break;case 15:VirtualProtect(p,4096,PAGE_READWRITE|PAGE_GUARD,&old);ret=reinterpret_cast<ULONG*>(1);break;}
  auto s=query(9,output,len,ret);MEMORY_BASIC_INFORMATION a{},b{};VirtualQuery(p,&a,sizeof(a));VirtualQuery(p+4096,&b,sizeof(b));VirtualProtect(p,8192,PAGE_READWRITE,&old);
  printf("pointer=%zu role=%u length=%lu status=%08lX output_protect=%08lX returned_protect=%08lX returned=%08lX bytes=",sizeof(void*),role,len,s,a.Protect,b.Protect,*reinterpret_cast<ULONG*>(p+4096));for(unsigned i=0;i<16;++i)printf("%02X",p[i]);printf("\n");
 }

 for(unsigned role=0;role<15;++role){
  VirtualProtect(p,8192,PAGE_READWRITE,&old);memset(p,0xA5,8192);ULONG version=1,flags=0x12345678;memcpy(p,&version,4);memcpy(p+4,&flags,4);
  auto output=static_cast<void*>(p);auto ret=reinterpret_cast<ULONG*>(p+4096);ULONG len=8;
  switch(role){case 0:ret=reinterpret_cast<ULONG*>(p);break;case 1:ret=reinterpret_cast<ULONG*>(p+4);break;case 2:ret=reinterpret_cast<ULONG*>(p+1);break;case 3:len=7;ret=reinterpret_cast<ULONG*>(1);break;case 4:VirtualProtect(p,4096,PAGE_READWRITE|PAGE_GUARD,&old);VirtualProtect(p+4096,4096,PAGE_NOACCESS,&old);break;case 5:VirtualProtect(p,4096,PAGE_NOACCESS,&old);VirtualProtect(p+4096,4096,PAGE_READWRITE|PAGE_GUARD,&old);break;case 6:VirtualProtect(p,4096,PAGE_READONLY,&old);VirtualProtect(p+4096,4096,PAGE_READWRITE|PAGE_GUARD,&old);break;case 7:output=p+4088;memcpy(output,&version,4);memcpy(static_cast<unsigned char*>(output)+4,&flags,4);VirtualProtect(p+4096,4096,PAGE_NOACCESS,&old);ret=reinterpret_cast<ULONG*>(p+128);break;case 8:output=p+4092;memcpy(output,&version,4);memcpy(static_cast<unsigned char*>(output)+4,&flags,4);VirtualProtect(p+4096,4096,PAGE_NOACCESS,&old);ret=reinterpret_cast<ULONG*>(p+128);break;case 9:output=nullptr;len=0;break;case 10:ret=reinterpret_cast<ULONG*>(p+4094);break;case 11:VirtualProtect(p,4096,PAGE_READONLY,&old);ret=nullptr;break;case 12:VirtualProtect(p,4096,PAGE_READONLY,&old);ret=reinterpret_cast<ULONG*>(1);break;case 13:VirtualProtect(p,4096,PAGE_READONLY|PAGE_GUARD,&old);ret=nullptr;break;case 14:VirtualProtect(p+4096,4096,PAGE_READONLY|PAGE_GUARD,&old);break;}
  auto s=query(9,output,len,ret);MEMORY_BASIC_INFORMATION a{},b{};VirtualQuery(p,&a,sizeof(a));VirtualQuery(p+4096,&b,sizeof(b));VirtualProtect(p,8192,PAGE_READWRITE,&old);
  printf("pointer=%zu extra_role=%u length=%lu status=%08lX output_protect=%08lX returned_protect=%08lX returned=%08lX prefix=",sizeof(void*),role,len,s,a.Protect,b.Protect,*reinterpret_cast<ULONG*>(p+4096));for(unsigned i=0;i<16;++i)printf("%02X",p[i]);printf("\n");
 }
 VirtualFree(p,0,MEM_RELEASE);
}
