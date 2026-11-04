#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stddef.h>

using CreateSection = LONG (NTAPI *)(HANDLE *, ULONG, void *, LONGLONG *, ULONG, ULONG, HANDLE);
using QuerySection = LONG (NTAPI *)(HANDLE, ULONG, void *, SIZE_T, SIZE_T *);
using MapSection = LONG (NTAPI *)(HANDLE, HANDLE, void **, ULONG_PTR, SIZE_T, LONGLONG *, SIZE_T *, ULONG, ULONG, ULONG);
using UnmapSection = LONG (NTAPI *)(HANDLE, void *);
using QueryObject = LONG (NTAPI *)(HANDLE, ULONG, void *, ULONG, ULONG *);
static CreateSection create_section;
static QuerySection query_section;
static MapSection map_section;
static UnmapSection unmap_section;
static QueryObject query_object;
static HANDLE output;
static unsigned case_index;
static volatile char line[16384];
static unsigned used;
static unsigned char seed[65536];

extern "C" __declspec(noinline) void *memset(void *p, int value, size_t n) {
  auto bytes=static_cast<volatile unsigned char *>(p);
  for(size_t i=0;i<n;++i)bytes[i]=static_cast<unsigned char>(value);
  return p;
}
extern "C" __declspec(noinline) void *memcpy(void *p, const void *q, size_t n) {
  auto destination=static_cast<volatile unsigned char *>(p);
  auto source=static_cast<const volatile unsigned char *>(q);
  for(size_t i=0;i<n;++i)destination[i]=source[i];
  return p;
}
static void flush() {
  DWORD written=0;
  if(!WriteFile(output,const_cast<const char *>(line),used,&written,nullptr)||written!=used)ExitProcess(90);
  used=0;
}
static void text(const char *value) {
  while(*value){if(used==sizeof(line))flush();line[used++]=*value++;}
}
static void decimal(ULONGLONG value) {
  if(value>0xFFFFFFFFULL)ExitProcess(89);ULONG number=static_cast<ULONG>(value);
  char digits[16];unsigned start=sizeof(digits);
  do{digits[--start]=char('0'+number%10);number/=10;}while(number);
  while(start<sizeof(digits)){char one[]={digits[start++],0};text(one);}
}
static void hex(const void *data,unsigned count) {
  const auto bytes=static_cast<const unsigned char *>(data);static const char digits[]="0123456789ABCDEF";
  for(unsigned i=0;i<count;++i){char pair[]={digits[bytes[i]>>4],digits[bytes[i]&15],0};text(pair);}
}
static void integer(ULONG value) {
  unsigned char bytes[]={static_cast<unsigned char>(value>>24),static_cast<unsigned char>(value>>16),static_cast<unsigned char>(value>>8),static_cast<unsigned char>(value)};
  text("\"0x");hex(bytes,4);text("\"");
}
static void field(const char *name,ULONGLONG value) { text(",\"");text(name);text("\":");decimal(value); }
static void status_field(const char *name,LONG value) { text(",\"");text(name);text("\":");integer(static_cast<ULONG>(value)); }

using StatusToError=ULONG (NTAPI *)(LONG);
extern "C" void entry() {
 output=GetStdHandle(STD_OUTPUT_HANDLE);HMODULE ntdll=GetModuleHandleW(L"ntdll.dll");
 auto convert=reinterpret_cast<StatusToError>(GetProcAddress(ntdll,"RtlNtStatusToDosError"));if(!convert)ExitProcess(2);
 text("{\"kind\":\"profile\",\"pointer_bytes\":");decimal(sizeof(void *));text("}\n");flush();
 const ULONG statuses[]={0xC000011E,0xC0000049,0xC000004E,0xC0000040,0xC000001F,0xC0000220};
 for(ULONG status:statuses){text("{\"kind\":\"case\",\"index\":");decimal(case_index++);status_field("status",static_cast<LONG>(status));field("error",convert(static_cast<LONG>(status)));text("}\n");flush();}ExitProcess(0);
}
