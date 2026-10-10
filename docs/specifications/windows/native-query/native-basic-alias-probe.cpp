#include <windows.h>
#include <cstdio>
#include <cstring>
#include <initializer_list>
using Q=LONG(NTAPI*)(ULONG,void*,ULONG,ULONG*);
int main(){auto q=reinterpret_cast<Q>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtQuerySystemInformation"));ULONG n=sizeof(void*)==4?44:64;alignas(16)unsigned char baseline[96],b[96];memset(baseline,0xa5,96);auto s=q(0,baseline,n,nullptr);if(s)return 1;for(unsigned at:{0u,1u,8u,24u,40u,60u}){memset(b,0xa5,96);s=q(0,b,n,reinterpret_cast<ULONG*>(b+at));auto expected=baseline;unsigned char copy[96];memcpy(copy,expected,96);memcpy(copy+at,&n,4);printf("pointer_bytes=%zu returned_offset=%u status=%08lX output_then_length=%d\n",sizeof(void*),at,s,memcmp(b,copy,96)==0);if(s||memcmp(b,copy,96))return 2;}}
