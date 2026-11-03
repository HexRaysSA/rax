
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stddef.h>
using Query = LONG (NTAPI *)(ULONG,void*,ULONG,ULONG*);
static const unsigned char packet[]={16,1,0,0,65,5,122,36,78,230,19,33,147,51,150,126,232,12,40,184,85,219,95,115,212,44,9,192,88,144,211,14,107,247,133,145,142,123,191,224,7,6,8,42,17,183,161,206,147,71,218,146,31,39,55,52,151,226,205,174,39,88,3,94,152,52,119,64,96,219,175,68,251,141,8,180,172,58,53,2,206,161,91,95,82,253,174,144,249,33,181,91,195,44,36,11,234,18,208,51,106,188,34,243,10,154,254,71,56,86,176,140,17,177,17,234,226,163,97,177,64,96,131,89,4,51,222,151,116,90,79,56,121,171,148,85,156,114,112,161,112,144,252,118,63,190,90,98,107,238,223,231,166,54,197,23,185,176,109,122,131,148,134,15,7,18,47,202,95,103,213,58,115,180,182,6,149,36,182,205,53,44,45,24,229,87,127,116,165,31,123,95,3,74,71,229,243,149,98,80,224,17,45,214,32,240,54,131,19,235,174,32,253,182,71,208,214,108,175,73,4,68,214,52,32,197,158,225,230,212,159,205,121,70,18,168,94,200,116,165,253,9,80,133,165,99,9,87,23,109,166,168,185,135,157,208,67,81,19,208,222,55,83,71,51,90,122,145,179,0,0,0,0,0,0,0,160,0,0,0,201,152,229,27,163,169,99,46,86,225,226,83,224,101,119,124,62,38,61,52,95,185,135,206,134,169,231,242,152,8,131,20,133,30,131,145,157,189,60,195,34,12,33,190,74,120,5,178,206,45,14,11,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,29,14,15,9,27,1,26,24,30,5,11,25,2,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,8,0,0,0,88,74,181,177,23,203,30,200};
static HANDLE output;
static void emit(const char *s,unsigned n) {DWORD written=0;if(!WriteFile(output,s,n,&written,nullptr)||written!=n)ExitProcess(90);}
static void text(const char *s) {unsigned n=0;while(s[n])++n;emit(s,n);}
static void number(unsigned long n) {char b[16];unsigned p=sizeof(b);do{b[--p]=char('0'+n%10);n/=10;}while(n);emit(b+p,unsigned(sizeof(b)-p));}
static void hex(const unsigned char *b,unsigned n) {static const char digits[]="0123456789ABCDEF";for(unsigned i=0;i<n;++i){char s[2]={digits[b[i]>>4],digits[b[i]&15]};emit(s,2);}}
static void integer(unsigned long n) {unsigned char b[4]={static_cast<unsigned char>(n>>24),static_cast<unsigned char>(n>>16),static_cast<unsigned char>(n>>8),static_cast<unsigned char>(n)};text("\"0x");hex(b,4);text("\"");}
static __declspec(noinline) void fill(volatile unsigned char *p,unsigned n,unsigned char v) {for(unsigned i=0;i<n;++i)p[i]=v;}
static void put(unsigned char *p,ULONG_PTR value,unsigned bytes) {for(unsigned i=0;i<bytes;++i){p[i]=static_cast<unsigned char>(value);value>>=8;}}
static ULONG get(const unsigned char *p) {return ULONG(p[0])|(ULONG(p[1])<<8)|(ULONG(p[2])<<16)|(ULONG(p[3])<<24);}
extern "C" void entry() {
 output=GetStdHandle(STD_OUTPUT_HANDLE);
 auto query=reinterpret_cast<Query>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtQuerySystemInformation"));if(!query)ExitProcess(2);
 constexpr unsigned ptr=sizeof(void*),size_at=2*ptr,outsize_at=2*ptr+4,version_at=2*ptr+8;
 const ULONG lengths[]={0,1,16,19,20,21,23,24,27,28,31,32,33,40,64};
 const ULONG versions[]={0,1,0xFFFFFFFF};
 text("{\"kind\":\"profile\",\"pointer_bytes\":");number(ptr);text("}\n");
 for(ULONG length:lengths)for(ULONG version:versions)for(unsigned want_return=0;want_return<2;++want_return)for(unsigned alignment_index=0;alignment_index<5;++alignment_index) {
  const unsigned offsets[]={0,1,2,4,8};unsigned offset=offsets[alignment_index];
  alignas(16) unsigned char storage[160],data[512];fill(storage,sizeof(storage),0xA5);fill(data,sizeof(data),0x5A);auto *p=storage+offset;
  put(p,reinterpret_cast<ULONG_PTR>(packet),ptr);put(p+ptr,reinterpret_cast<ULONG_PTR>(data),ptr);put(p+size_at,sizeof(packet),4);put(p+outsize_at,sizeof(data),4);put(p+version_at,version,4);
  ULONG returned=0xFEEDFACE;LONG status=query(134,p,length,want_return?&returned:nullptr);
  text("{\"kind\":\"abi\",\"length\":");number(length);text(",\"version\":");number(version);text(",\"offset\":");number(offset);text(",\"want_return\":");number(want_return);text(",\"status\":");integer(static_cast<ULONG>(status));text(",\"returned\":");number(returned);text(",\"output_size\":");number(get(p+outsize_at));text(",\"descriptor_tail\":\"");hex(p+version_at+4,8);text("\",\"output_prefix\":\"");hex(data,8);text("\"}\n");
 }
 ExitProcess(0);
}
