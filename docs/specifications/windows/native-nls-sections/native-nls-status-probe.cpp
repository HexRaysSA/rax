#include <windows.h>
#include <cstdio>
#include <initializer_list>
using Convert=ULONG(NTAPI*)(LONG);
int main(){auto f=reinterpret_cast<Convert>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"RtlNtStatusToDosError"));if(!f)return 1;printf("pointer=%zu\n",sizeof(void*));for(ULONG s:{0xC0000019u,0xC000001Bu,0xC0000021u,0xC0000045u})printf("status=%08lX dos=%lu\n",s,f(LONG(s)));}
