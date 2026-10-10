#include <windows.h>
#include <cstdio>
#include <cstring>
#include <initializer_list>
using Q=LONG(NTAPI*)(HANDLE,ULONG,void*,ULONG,ULONG*);
int main(){auto q=reinterpret_cast<Q>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtQueryInformationProcess"));if(!q)return 1;
for(ULONG cls:{0u,36u,65535u})for(ULONG n:{0u,3u,4u,5u,23u,24u,25u,47u,48u,49u,64u}){alignas(16)unsigned char b[96];memset(b,0xa5,sizeof(b));ULONG r=0xa5a5a5a5;auto s=q(GetCurrentProcess(),cls,b,n,&r);printf("width=%zu class=%lu bytes=%lu status=%08lX returned=%08lX out=",sizeof(void*),cls,n,s,r);for(unsigned i=0;i<64;i++)printf("%02x",b[i]);putchar('\n');}
struct C{const char* name;int handle,out,ret;ULONG n;};for(auto c:{C{"nulloutput",0,1,0,4},C{"badoutput",0,2,0,4},C{"unaligned",0,3,0,4},C{"badreturn",0,0,1,4},C{"unalignedret",0,0,2,4},C{"nullret",0,0,3,4},C{"nullhandle",1,0,0,4},C{"badhandle",2,0,0,4},C{"badhandle-short",2,0,0,3},C{"badhandle-badout",2,2,0,4},C{"badhandle-nullout",2,1,0,4},C{"badhandle-badret",2,0,1,4}}){alignas(16)unsigned char b[32],r[16];memset(b,0xa5,sizeof(b));memset(r,0xa5,sizeof(r));auto s=q(c.handle==1?nullptr:c.handle==2?reinterpret_cast<HANDLE>(1):GetCurrentProcess(),36,c.out==1?nullptr:c.out==2?reinterpret_cast<void*>(1):c.out==3?b+1:b,c.n,c.ret==1?reinterpret_cast<ULONG*>(1):c.ret==2?reinterpret_cast<ULONG*>(r+1):c.ret==3?nullptr:reinterpret_cast<ULONG*>(r));printf("%s status=%08lX out=",c.name,s);for(unsigned i=0;i<8;i++)printf("%02x",b[i]);printf(" ret=");for(unsigned i=0;i<8;i++)printf("%02x",r[i]);putchar('\n');}}
