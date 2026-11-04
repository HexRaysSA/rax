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
static ULONG load(void *base) {
  if(!base)return 0xFFFFFFFF;
  unsigned char byte=0;SIZE_T count=0;
  if(!ReadProcessMemory(GetCurrentProcess(),base,&byte,1,&count)||count!=1)return 0xFFFFFFFE;
  return byte;
}
static __declspec(noinline) void raw_store(void *base,unsigned char value) { *static_cast<volatile unsigned char *>(base)=value; }
static __declspec(noinline) ULONG store(void *base,unsigned char value) {
  if(!base)return 0xFFFFFFFF;
  ULONG exception=0;
  __try {raw_store(base,value);}
  __except(EXCEPTION_EXECUTE_HANDLER){exception=GetExceptionCode();}
  return exception;
}
static void change_file(HANDLE file,LONGLONG offset,unsigned char value) {
  LARGE_INTEGER position;position.QuadPart=offset;
  if(!SetFilePointerEx(file,position,nullptr,FILE_BEGIN))ExitProcess(31);
  DWORD written=0;if(!WriteFile(file,&value,1,&written,nullptr)||written!=1)ExitProcess(32);
}
static ULONG file_byte(HANDLE file) {
  LARGE_INTEGER position;position.QuadPart=0;
  if(!SetFilePointerEx(file,position,nullptr,FILE_BEGIN))ExitProcess(33);
  unsigned char byte=0;DWORD count=0;if(!ReadFile(file,&byte,1,&count,nullptr)||count!=1)ExitProcess(34);
  return byte;
}

using QueryMemory=LONG (NTAPI *)(HANDLE,void *,ULONG,void *,SIZE_T,SIZE_T *);
static QueryMemory query_memory;
static void protect_case(HANDLE section,ULONG section_protection,ULONG initial,ULONG protection) {
  void *base=nullptr;SIZE_T size=0;LONGLONG offset=0;
  LONG mapped=map_section(section,GetCurrentProcess(),&base,0,0,&offset,&size,2,0,initial);
  alignas(8) unsigned char before[48],after[48];memset(before,0xA5,48);memset(after,0xA5,48);SIZE_T returned=0;LONG before_status=static_cast<LONG>(0xDEADBEEF),after_status=before_status;DWORD old=0xA5A5A5A5,error=0;BOOL changed=FALSE;ULONG exception=0xDEADBEEF;MEMORY_BASIC_INFORMATION region;memset(&region,0,sizeof(region));
  if(mapped>=0&&base){before_status=query_memory(GetCurrentProcess(),base,3,before,48,&returned);memset(before,0,sizeof(void *));SetLastError(0);changed=VirtualProtect(base,4096,protection,&old);error=GetLastError();if(changed)exception=store(base,0x77);VirtualQuery(base,&region,sizeof(region));after_status=query_memory(GetCurrentProcess(),base,3,after,48,&returned);memset(after,0,sizeof(void *));if(unmap_section(GetCurrentProcess(),base)!=0)ExitProcess(74);}
  text("{\"kind\":\"protect\",\"index\":");decimal(case_index++);status_field("section_protection",section_protection);status_field("initial_protection",initial);status_field("protection",protection);status_field("map_status",mapped);field("changed",changed);field("error",error);status_field("old",old);status_field("write_exception",exception);status_field("reported_protection",region.Protect);status_field("before_region_status",before_status);status_field("after_region_status",after_status);text(",\"before_region_hex\":\"");hex(before,48);text("\",\"after_region_hex\":\"");hex(after,48);text("\"}\n");flush();
}

extern "C" void entry() {
 output=GetStdHandle(STD_OUTPUT_HANDLE);HMODULE ntdll=GetModuleHandleW(L"ntdll.dll");
 create_section=reinterpret_cast<CreateSection>(GetProcAddress(ntdll,"NtCreateSection"));map_section=reinterpret_cast<MapSection>(GetProcAddress(ntdll,"NtMapViewOfSection"));unmap_section=reinterpret_cast<UnmapSection>(GetProcAddress(ntdll,"NtUnmapViewOfSection"));query_memory=reinterpret_cast<QueryMemory>(GetProcAddress(ntdll,"NtQueryVirtualMemory"));if(!create_section||!map_section||!unmap_section||!query_memory)ExitProcess(2);
 void *check=VirtualAlloc(nullptr,4096,MEM_RESERVE|MEM_COMMIT,PAGE_READONLY);if(!check)ExitProcess(3);ULONG seh=store(check,0x22);if(seh!=0xC0000005||!VirtualFree(check,0,MEM_RELEASE))ExitProcess(4);
 const wchar_t *name=L"transitions-owned-file.bin";if(GetFileAttributesW(name)!=INVALID_FILE_ATTRIBUTES)ExitProcess(5);
 HANDLE file=CreateFileW(name,GENERIC_ALL,7,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);if(file==INVALID_HANDLE_VALUE)ExitProcess(6);change_file(file,0,0x11);change_file(file,65536,0x66);
 text("{\"kind\":\"profile\",\"pointer_bytes\":");decimal(sizeof(void *));status_field("seh_preflight",seh);text("}\n");flush();
 const ULONG sections[]={2,4,8,0x10,0x20,0x40,0x80},pages[]={1,2,4,8,0x10,0x20,0x40,0x80};
 for(ULONG section_protection:sections){HANDLE section=nullptr;LONG status=create_section(&section,0xF001F,nullptr,nullptr,section_protection,0x08000000,file);if(status!=0||!section)ExitProcess(7);
  for(ULONG initial:pages)for(ULONG page:pages){change_file(file,0,0x11);protect_case(section,section_protection,initial,page);}CloseHandle(section);
 }
 CloseHandle(file);if(!DeleteFileW(name))ExitProcess(8);ExitProcess(0);
}
