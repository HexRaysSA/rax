#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <cstdio>
static HANDLE release_worker;
static DWORD WINAPI worker(void*) {return WaitForSingleObject(release_worker,30000)==WAIT_OBJECT_0?12:13;}
int main() {
 release_worker=CreateEventW(nullptr,TRUE,FALSE,nullptr);if(!release_worker)return 11;
 auto thread=CreateThread(nullptr,0,worker,nullptr,CREATE_SUSPENDED,nullptr);if(!thread)return 12;
 CONTEXT original={};original.ContextFlags=CONTEXT_ALL;if(!GetThreadContext(thread,&original))return 13;
 const DWORD masks[]={0,0x40,0x80,0xc0,4,0x44,0x84,0xc4};unsigned failures=0;
 for(auto mask:masks) {
  auto initial=original;initial.ContextFlags=CONTEXT_FLOATING_POINT;initial.Fpcr=1u<<22;initial.Fpsr=1;
  for(unsigned i=0;i<32;++i){initial.V[i].Low=0x1020+i;initial.V[i].High=0x11220000+i;}
  if(!SetThreadContext(thread,&initial))return 14;
  auto input=initial;input.ContextFlags=CONTEXT_ARM64|mask;input.Fpcr=1u<<23;input.Fpsr=2;
  for(unsigned i=0;i<32;++i){input.V[i].Low=0x5060+i;input.V[i].High=0x33440000+i;}
  SetLastError(0);BOOL set=SetThreadContext(thread,&input);auto error=GetLastError();
  CONTEXT output={};output.ContextFlags=CONTEXT_FLOATING_POINT;BOOL get=GetThreadContext(thread,&output);unsigned mismatches=0;
  for(unsigned i=0;i<32;++i){bool changed=(mask&(i<16?0x44:0x84))!=0;auto& expected=changed?input:initial;if(output.V[i].Low!=expected.V[i].Low||output.V[i].High!=expected.V[i].High)++mismatches;}
  bool low=(mask&0x44)!=0;auto& expected=low?input:initial;if(output.Fpcr!=expected.Fpcr||output.Fpsr!=expected.Fpsr)++mismatches;
  std::printf("{\"flags\":%lu,\"set\":%d,\"error\":%lu,\"get\":%d,\"mismatches\":%u,\"fpcr\":%lu,\"fpsr\":%lu}\n",mask,int(set),error,int(get),mismatches,output.Fpcr,output.Fpsr);
  std::printf("{\"kind\":\"vectors\",\"flags\":%lu,\"low\":[",mask);
  for(unsigned i=0;i<32;++i)std::printf("%s%llu",i?",":"",output.V[i].Low);
  std::printf("],\"high\":[");
  for(unsigned i=0;i<32;++i)std::printf("%s%llu",i?",":"",static_cast<unsigned long long>(output.V[i].High));
  std::printf("]}\n");
  failures+=!set||!get||mismatches;
 }
 if(!SetThreadContext(thread,&original)||!SetEvent(release_worker)||ResumeThread(thread)!=1)return 15;
 if(WaitForSingleObject(thread,30000)!=WAIT_OBJECT_0)return 16;DWORD code=0;if(!GetExitCodeThread(thread,&code)||code!=12)return 17;
 if(!CloseHandle(thread)||!CloseHandle(release_worker))return 18;
 return failures?19:0;
}
