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

static unsigned char *arena;
static HANDLE files[2];
static ULONG page_protection(unsigned page) {
  MEMORY_BASIC_INFORMATION info;
  if(!VirtualQuery(arena+page*4096,&info,sizeof(info)))ExitProcess(70);
  return info.Protect;
}
static void reset_pages() {
  DWORD old;
  if(!VirtualProtect(arena,4*4096,PAGE_READWRITE,&old))ExitProcess(71);
  memset(arena,0xA5,4*4096);
}
static void permission(unsigned page,ULONG protection) {
  DWORD old;
  if(!VirtualProtect(arena+page*4096,4096,protection,&old))ExitProcess(72);
}
static LONG create_call(HANDLE *out,void *oa,LONGLONG *maximum,ULONG protect,HANDLE file,ULONG *exception) {
  LONG status=static_cast<LONG>(0xDEADBEEF);
  __try{status=create_section(out,0xF001F,oa,maximum,protect,0x08000000,file);}
  __except(EXCEPTION_EXECUTE_HANDLER){*exception=GetExceptionCode();}
  return status;
}
struct Attributes {ULONG length;HANDLE root;void *name;ULONG flags;void *security;void *qos;};
static unsigned handle_role;
static LONG query_call(HANDLE section,ULONG klass,void *buffer,SIZE_T bytes,SIZE_T *returned,ULONG *exception) {
  LONG status=static_cast<LONG>(0xDEADBEEF);
  __try{status=query_section(section,klass,buffer,bytes,returned);}
  __except(EXCEPTION_EXECUTE_HANDLER){*exception=GetExceptionCode();}
  return status;
}
static void query_case(HANDLE section,unsigned mode,unsigned klass,unsigned bytes) {
  reset_pages();void *buffer=arena;auto returned=reinterpret_cast<SIZE_T *>(arena+4096);
  switch(mode){case 1:buffer=nullptr;break;case 2:buffer=reinterpret_cast<void *>(1);break;case 3:permission(0,PAGE_NOACCESS);break;case 4:permission(0,PAGE_READONLY);break;case 5:permission(0,PAGE_READWRITE|PAGE_GUARD);break;case 6:buffer=arena+1;break;case 7:returned=nullptr;break;case 8:returned=reinterpret_cast<SIZE_T *>(1);break;case 9:permission(1,PAGE_READONLY);break;case 10:permission(1,PAGE_READWRITE|PAGE_GUARD);break;case 11:buffer=arena+4;break;case 12:returned=reinterpret_cast<SIZE_T *>(arena+4097);break;case 13:returned=reinterpret_cast<SIZE_T *>(arena+4100);break;}
  ULONG exception=0;LONG status=query_call(section,klass,buffer,bytes,returned,&exception);
  const ULONG data_page=page_protection(0),return_page=page_protection(1);
  permission(0,PAGE_READWRITE);permission(1,PAGE_READWRITE);
  text("{\"kind\":\"query\",\"index\":");decimal(case_index++);field("handle_role",handle_role);field("mode",mode);field("class",klass);field("bytes",bytes);status_field("status",status);status_field("exception",exception);status_field("data_page",data_page);status_field("return_page",return_page);text(",\"data_hex\":\"");hex(arena,40);text("\",\"return_hex\":\"");hex(arena+4096,sizeof(SIZE_T));text("\"}\n");flush();
}

extern "C" void entry() {
 output=GetStdHandle(STD_OUTPUT_HANDLE);HMODULE ntdll=GetModuleHandleW(L"ntdll.dll");
 create_section=reinterpret_cast<CreateSection>(GetProcAddress(ntdll,"NtCreateSection"));query_section=reinterpret_cast<QuerySection>(GetProcAddress(ntdll,"NtQuerySection"));if(!create_section||!query_section)ExitProcess(2);
 arena=static_cast<unsigned char *>(VirtualAlloc(nullptr,4*4096,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE));if(!arena)ExitProcess(3);
 void *check=VirtualAlloc(nullptr,4096,MEM_RESERVE|MEM_COMMIT,PAGE_READONLY);if(!check)ExitProcess(4);ULONG seh=store(check,0x22);if(seh!=0xC0000005||!VirtualFree(check,0,MEM_RELEASE))ExitProcess(5);
 const wchar_t *name=L"query-owned-file.bin";if(GetFileAttributesW(name)!=INVALID_FILE_ATTRIBUTES)ExitProcess(6);HANDLE file=CreateFileW(name,GENERIC_READ|GENERIC_WRITE,7,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);if(file==INVALID_HANDLE_VALUE)ExitProcess(7);change_file(file,0,0x11);change_file(file,65536,0x66);
 HANDLE section=nullptr,no_query=nullptr,event=CreateEventW(nullptr,FALSE,FALSE,nullptr);if(!event||create_section(&section,1,nullptr,nullptr,2,0x08000000,file)!=0||create_section(&no_query,4,nullptr,nullptr,2,0x08000000,file)!=0)ExitProcess(8);
 text("{\"kind\":\"profile\",\"pointer_bytes\":");decimal(sizeof(void *));status_field("seh_preflight",seh);text("}\n");flush();
 const unsigned sizes[]={0,1,3,4,7,8,15,16,23,24,32,47,48,63,64,80};
 for(unsigned klass=0;klass<6;++klass)for(unsigned mode=0;mode<14;++mode)for(unsigned size:sizes)query_case(section,mode,klass,size);
 HANDLE handles[]={section,no_query,nullptr,GetCurrentProcess(),event};const unsigned modes[]={0,1,2,9,10},short_sizes[]={0,16,24,64};
 for(handle_role=1;handle_role<5;++handle_role)for(unsigned klass=0;klass<3;++klass)for(unsigned mode:modes)for(unsigned size:short_sizes)query_case(handles[handle_role],mode,klass,size);
 CloseHandle(section);CloseHandle(no_query);CloseHandle(event);CloseHandle(file);if(!DeleteFileW(name)||!VirtualFree(arena,0,MEM_RELEASE))ExitProcess(9);ExitProcess(0);
}
