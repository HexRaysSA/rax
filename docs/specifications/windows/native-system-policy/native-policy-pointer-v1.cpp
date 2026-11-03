
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
using Query=LONG (NTAPI *)(ULONG,void*,ULONG,ULONG*);
static const unsigned char packet[]={16,1,0,0,65,5,122,36,78,230,19,33,147,51,150,126,232,12,40,184,85,219,95,115,212,44,9,192,88,144,211,14,107,247,133,145,142,123,191,224,7,6,8,42,17,183,161,206,147,71,218,146,31,39,55,52,151,226,205,174,39,88,3,94,152,52,119,64,96,219,175,68,251,141,8,180,172,58,53,2,206,161,91,95,82,253,174,144,249,33,181,91,195,44,36,11,234,18,208,51,106,188,34,243,10,154,254,71,56,86,176,140,17,177,17,234,226,163,97,177,64,96,131,89,4,51,222,151,116,90,79,56,121,171,148,85,156,114,112,161,112,144,252,118,63,190,90,98,107,238,223,231,166,54,197,23,185,176,109,122,131,148,134,15,7,18,47,202,95,103,213,58,115,180,182,6,149,36,182,205,53,44,45,24,229,87,127,116,165,31,123,95,3,74,71,229,243,149,98,80,224,17,45,214,32,240,54,131,19,235,174,32,253,182,71,208,214,108,175,73,4,68,214,52,32,197,158,225,230,212,159,205,121,70,18,168,94,200,116,165,253,9,80,133,165,99,9,87,23,109,166,168,185,135,157,208,67,81,19,208,127,105,154,213,130,254,104,5,183,0,0,0,0,0,0,0,160,0,0,0,201,152,229,27,163,169,99,46,86,225,226,83,224,101,119,124,62,38,61,52,95,185,135,206,134,169,231,242,152,8,131,20,133,30,131,145,157,189,60,195,34,12,33,190,74,120,5,178,206,45,14,11,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,29,14,15,9,27,1,26,24,30,5,11,25,2,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,8,0,0,0,88,74,181,177,23,203,30,200};
static HANDLE stream;
static volatile char line[16384];static unsigned count;
static void flush(){DWORD n=0;if(!WriteFile(stream,const_cast<const char*>(line),count,&n,nullptr)||n!=count)ExitProcess(90);count=0;}
static void emit(const char *p,unsigned n){for(unsigned i=0;i<n;++i){if(count==sizeof(line))flush();line[count++]=p[i];}}
static void text(const char *s){unsigned n=0;while(s[n])++n;emit(s,n);}
static void number(ULONG n){char b[16];unsigned p=sizeof(b);do{b[--p]=char('0'+n%10);n/=10;}while(n);emit(b+p,unsigned(sizeof(b)-p));}
static void hex(const unsigned char *p,unsigned n){static const char d[]="0123456789ABCDEF";for(unsigned i=0;i<n;++i){char s[2]={d[p[i]>>4],d[p[i]&15]};emit(s,2);}}
static void integer(ULONG n){unsigned char b[4]={static_cast<unsigned char>(n>>24),static_cast<unsigned char>(n>>16),static_cast<unsigned char>(n>>8),static_cast<unsigned char>(n)};text("\"0x");hex(b,4);text("\"");}
static __declspec(noinline) void fill(volatile unsigned char *p,unsigned n,unsigned char c){for(unsigned i=0;i<n;++i)p[i]=c;}
static __declspec(noinline) void copy(volatile unsigned char *p,const volatile unsigned char *q,unsigned n){for(unsigned i=0;i<n;++i)p[i]=q[i];}
static void put(unsigned char *p,ULONG_PTR n,unsigned size){for(unsigned i=0;i<size;++i){p[i]=static_cast<unsigned char>(n);n>>=8;}}
static LONG checked(Query q,void *p,ULONG size,ULONG *returned,LONG *exception){LONG status=static_cast<LONG>(0xDEADBEEF);__try{status=q(134,p,size,returned);}__except(EXCEPTION_EXECUTE_HANDLER){*exception=static_cast<LONG>(GetExceptionCode());}return status;}
static unsigned char *arena,*before;static Query query;static unsigned records;
static void protect(unsigned page,DWORD flags){DWORD old=0;if(!VirtualProtect(arena+page*4096,4096,flags,&old))ExitProcess(10);}
static void observe(unsigned d,unsigned in,unsigned out,unsigned ret,ULONG length){
 constexpr unsigned ptr=sizeof(void*),size_at=2*ptr;for(unsigned i=0;i<8;++i)protect(i,PAGE_READWRITE);fill(arena,32768,0xA5);
 ULONG da=128,ia=8192+128,oa=16384+128,ra=24576+128;ULONG input_size=sizeof(packet),capacity=512;
 if(d==2)++da;if(d>=7)da=4096-12;
 if(in>=6)ia=8192+4096-128;
 if(out==2)++oa;if(out>=7)oa=16384+4096-128;if(out==10)oa=ia;
 if(ret==2)++ra;if(ret==7)ra=da+size_at+4;if(ret==8)ra=da;if(ret==9)ra=ia;if(ret==10)ra=oa;if(ret==11)ra=24576+4094;
 if(in==5)input_size=0;
 unsigned char *descriptor=d==1?nullptr:arena+da;unsigned char *input=in==1?nullptr:arena+ia;unsigned char *output=out==1?nullptr:arena+oa;ULONG *returned=ret==1?nullptr:reinterpret_cast<ULONG*>(arena+ra);
 copy(arena+ia,packet,sizeof(packet));put(arena+da,reinterpret_cast<ULONG_PTR>(input),ptr);put(arena+da+ptr,reinterpret_cast<ULONG_PTR>(output),ptr);put(arena+da+size_at,input_size,4);put(arena+da+size_at+4,capacity,4);put(arena+da+size_at+8,0,4);put(arena+24576+128,0xFEEDFACE,4);copy(before,arena,32768);
 if(d==3)protect(0,PAGE_READONLY);if(d==4)protect(0,PAGE_NOACCESS);if(d==5)protect(0,PAGE_READWRITE|PAGE_GUARD);if(d==6)protect(0,PAGE_READONLY|PAGE_GUARD);if(d==7)protect(1,PAGE_NOACCESS);if(d==8)protect(1,PAGE_READONLY);
 if(in==2)protect(2,PAGE_NOACCESS);if(in==3)protect(2,PAGE_READWRITE|PAGE_GUARD);if(in==4)protect(2,PAGE_READONLY|PAGE_GUARD);if(in==6)protect(3,PAGE_NOACCESS);if(in==7)protect(3,PAGE_READWRITE|PAGE_GUARD);
 if(out==3)protect(4,PAGE_READONLY);if(out==4)protect(4,PAGE_NOACCESS);if(out==5)protect(4,PAGE_READWRITE|PAGE_GUARD);if(out==6)protect(4,PAGE_READONLY|PAGE_GUARD);if(out==7)protect(5,PAGE_NOACCESS);if(out==8)protect(5,PAGE_READWRITE|PAGE_GUARD);if(out==9)protect(5,PAGE_READONLY);
 if(ret==3)protect(6,PAGE_READONLY);if(ret==4)protect(6,PAGE_NOACCESS);if(ret==5)protect(6,PAGE_READWRITE|PAGE_GUARD);if(ret==6)protect(6,PAGE_READONLY|PAGE_GUARD);if(ret==11)protect(7,PAGE_NOACCESS);
 LONG exception=0,status=checked(query,descriptor,length,returned,&exception);DWORD protections[8];
 for(unsigned i=0;i<8;++i){MEMORY_BASIC_INFORMATION info;if(!VirtualQuery(arena+4096*i,&info,sizeof(info)))ExitProcess(11);protections[i]=info.Protect;protect(i,PAGE_READWRITE);}
 text("{\"kind\":\"case\",\"index\":");number(records++);text(",\"roles\":[");number(d);text(",");number(in);text(",");number(out);text(",");number(ret);text("],\"length\":");number(length);text(",\"status\":");integer(static_cast<ULONG>(status));text(",\"exception\":");integer(static_cast<ULONG>(exception));text(",\"protections\":[");for(unsigned i=0;i<8;++i){if(i)text(",");number(protections[i]);}text("],\"changes\":[");
 bool comma=false;unsigned at=0;while(at<32768){if(arena[at]==before[at]){++at;continue;}unsigned start=at;while(at<32768&&arena[at]!=before[at])++at;if(comma)text(",");comma=true;text("[");number(start);text(",\"");hex(arena+start,at-start);text("\"]");}text("]}\n");flush();
}
extern "C" void entry(){stream=GetStdHandle(STD_OUTPUT_HANDLE);query=reinterpret_cast<Query>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtQuerySystemInformation"));if(!query)ExitProcess(2);
 constexpr ULONG_PTR base=sizeof(void*)==8?static_cast<ULONG_PTR>(0x100000000ULL):static_cast<ULONG_PTR>(0x30000000);
 arena=static_cast<unsigned char*>(VirtualAlloc(reinterpret_cast<void*>(base),32768,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE));before=static_cast<unsigned char*>(VirtualAlloc(nullptr,32768,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE));if(reinterpret_cast<ULONG_PTR>(arena)!=base||!before)ExitProcess(3);
 text("{\"kind\":\"profile\",\"pointer_bytes\":");number(sizeof(void*));text(",\"base_hex\":\"");unsigned char encoded[sizeof(void*)];for(unsigned i=0;i<sizeof(void*);++i)encoded[sizeof(void*)-1-i]=static_cast<unsigned char>(base>>(8*i));hex(encoded,sizeof(encoded));text("\",\"input_hex\":\"");hex(packet,sizeof(packet));text("\"}\n");flush();
 constexpr ULONG length=sizeof(void*)==4?20:32;
 for(unsigned d=0;d<9;++d)for(unsigned r=0;r<12;++r){observe(d,0,0,r,0);observe(d,0,0,r,length);}
 const unsigned returns[]={0,1,3,4,5,7,10};for(unsigned i=0;i<8;++i)for(unsigned o=0;o<11;++o)for(unsigned r:returns)observe(0,i,o,r,length);
 VirtualFree(arena,0,MEM_RELEASE);VirtualFree(before,0,MEM_RELEASE);ExitProcess(0);}
