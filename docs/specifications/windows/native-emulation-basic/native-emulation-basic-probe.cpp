#include <windows.h>
#include <cstdio>
#include <cstring>
#include <initializer_list>
using Query=LONG(NTAPI*)(ULONG,void*,ULONG,ULONG*);
int main(){auto q=reinterpret_cast<Query>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtQuerySystemInformation"));if(!q)return 1;
for(ULONG cls:{0u,62u,114u})for(ULONG n:{0u,12u,43u,44u,45u,63u,64u,65u,80u}){alignas(16)unsigned char b[96];memset(b,0xA5,sizeof(b));ULONG ret=0xDEADBEEF;auto s=q(cls,b,n,&ret);printf("class=%lu width=%zu len=%lu status=%08lX required=%lu bytes=",cls,sizeof(void*),n,s,ret);for(unsigned i=0;i<96;i++)printf("%02x",b[i]);putchar('\n');}}
