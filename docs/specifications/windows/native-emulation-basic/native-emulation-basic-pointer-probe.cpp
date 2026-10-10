#include <windows.h>
#include <cstdio>
#include <cstring>
#include <initializer_list>
using Query = LONG(NTAPI*)(ULONG, void*, ULONG, ULONG*);
int main() {
 auto q=reinterpret_cast<Query>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtQuerySystemInformation"));if(!q) return 1;
 constexpr ULONG w=sizeof(void*)==4?44:64;
 struct Case {const char* name;ULONG cls;ULONG len;int out;int ret;};
 for(auto c:{Case{"exact",62,w,0,0},Case{"short",62,w-1,0,0},Case{"long",62,w+1,0,0},Case{"nulloutput",62,w,1,0},Case{"badoutput",62,w,3,0},Case{"unaligned-short",62,w-1,2,0},Case{"nulloutput-short",62,0,1,0},Case{"badreturn",62,w,0,1},Case{"unalignedout",62,w,2,0},Case{"aligned4out",62,w,4,0},Case{"unalignedret",62,w,0,2},Case{"nullret",62,w,0,3},Case{"invalidclass",65535,w,0,0},Case{"invalidclass-badret",65535,w,0,1}}){
  alignas(16) unsigned char b[96];std::memset(b,0xA5,sizeof(b));alignas(16) unsigned char r[16];std::memset(r,0xA5,sizeof(r));
  void* out=c.out==1?nullptr:c.out==2?b+1:c.out==3?reinterpret_cast<void*>(1):c.out==4?b+4:b;
  ULONG* ret=c.ret==1?reinterpret_cast<ULONG*>(1):c.ret==2?reinterpret_cast<ULONG*>(r+1):c.ret==3?nullptr:reinterpret_cast<ULONG*>(r);
  LONG status=q(c.cls,out,c.len,ret);
  std::printf("%s width=%lu status=%08lX out=",c.name,w,status);for(unsigned i=0;i<16;i++)std::printf("%02x",b[i]);std::printf(" ret=");for(unsigned i=0;i<8;i++)std::printf("%02x",r[i]);std::putchar('\n');
 }
}
