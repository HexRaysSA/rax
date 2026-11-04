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
static void observe(ULONG file_size,ULONG section_protection,ULONG view_protection,bool grow) {
  DWORD handles_before=0,handles_after=0;GetProcessHandleCount(GetCurrentProcess(),&handles_before);
  wchar_t name[]=L"coherence-00000.bin";unsigned number=case_index;
  for(unsigned digit=0;digit<5;++digit){name[14-digit]=wchar_t(L'0'+number%10);number/=10;}
  if(GetFileAttributesW(name)!=INVALID_FILE_ATTRIBUTES)ExitProcess(10);
  HANDLE writer=CreateFileW(name,GENERIC_READ|GENERIC_WRITE,7,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);if(writer==INVALID_HANDLE_VALUE)ExitProcess(11);
  DWORD written=0;ULONG first=file_size>sizeof(seed)?sizeof(seed):file_size;
  if(!WriteFile(writer,seed,first,&written,nullptr)||written!=first)ExitProcess(12);
  if(file_size>first&&(!WriteFile(writer,seed,file_size-first,&written,nullptr)||written!=file_size-first))ExitProcess(13);
  HANDLE file=CreateFileW(name,GENERIC_READ|GENERIC_WRITE,7,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);if(file==INVALID_HANDLE_VALUE)ExitProcess(14);
  HANDLE a=nullptr,b=nullptr;LONG create_a=create_section(&a,0xF001F,nullptr,nullptr,section_protection,0x08000000,file);
  LONG create_b=create_section(&b,0xF001F,nullptr,nullptr,section_protection,0x08000000,file);
  if(create_a<0||create_b<0||!a||!b)ExitProcess(15);
  void *views[4]={nullptr,nullptr,nullptr,nullptr};LONG statuses[4];SIZE_T sizes[4]={0,0,0,0};
  for(unsigned i=0;i<4;++i){LONGLONG offset=0;statuses[i]=map_section(i==2?b:a,GetCurrentProcess(),&views[i],0,0,&offset,&sizes[i],2,0,i==3?8:view_protection);if(statuses[i]<0)views[i]=nullptr;}
  ULONG phases[7][4],file_values[5];
  for(unsigned i=0;i<4;++i)phases[0][i]=load(views[i]);file_values[0]=file_byte(writer);
  change_file(writer,0,0x22);for(unsigned i=0;i<4;++i)phases[1][i]=load(views[i]);file_values[1]=file_byte(writer);
  ULONG write_exception=store(views[0],0x33);for(unsigned i=0;i<4;++i)phases[2][i]=load(views[i]);file_values[2]=file_byte(writer);
  ULONG cow_exception=store(views[3],0x44);for(unsigned i=0;i<4;++i)phases[3][i]=load(views[i]);file_values[3]=file_byte(writer);
  change_file(writer,0,0x55);for(unsigned i=0;i<4;++i)phases[4][i]=load(views[i]);file_values[4]=file_byte(writer);
  void *growth_view=nullptr;SIZE_T growth_size=0;HANDLE growth_section=nullptr;
  LONG growth_create=static_cast<LONG>(0xDEADBEEF),growth_map=growth_create,growth_query=growth_create;
  alignas(8) unsigned char growth_basic[24];memset(growth_basic,0xA5,sizeof(growth_basic));SIZE_T growth_return=0;
  ULONG growth_first=0xFFFFFFFF,growth_last=0xFFFFFFFF;
  if(grow){
    change_file(writer,65536,0x66);
    growth_create=create_section(&growth_section,0xF001F,nullptr,nullptr,2,0x08000000,file);
    if(growth_create>=0&&growth_section){LONGLONG offset=0;growth_query=query_section(growth_section,0,growth_basic,sizeof(growth_basic),&growth_return);growth_map=map_section(growth_section,GetCurrentProcess(),&growth_view,0,0,&offset,&growth_size,2,0,2);if(growth_map>=0&&growth_view){growth_first=load(growth_view);growth_last=load(static_cast<unsigned char *>(growth_view)+65536);}else growth_view=nullptr;}
  }
  LARGE_INTEGER length;if(!GetFileSizeEx(file,&length))ExitProcess(16);
  CloseHandle(file);CloseHandle(writer);CloseHandle(a);CloseHandle(b);if(growth_section)CloseHandle(growth_section);
  for(unsigned i=0;i<4;++i)phases[5][i]=load(views[i]);
  BOOL deleted=DeleteFileW(name);DWORD delete_error=deleted?0:GetLastError();
  for(unsigned i=0;i<4;++i)phases[6][i]=load(views[i]);
  LONG unmapped[4];for(unsigned i=0;i<4;++i)unmapped[i]=views[i]?unmap_section(GetCurrentProcess(),views[i]):static_cast<LONG>(0xDEADBEEF);
  if(growth_view&&unmap_section(GetCurrentProcess(),growth_view)!=0)ExitProcess(17);
  BOOL exists=GetFileAttributesW(name)!=INVALID_FILE_ATTRIBUTES;if(exists&&!DeleteFileW(name))ExitProcess(18);
  GetProcessHandleCount(GetCurrentProcess(),&handles_after);
  text("{\"kind\":\"case\",\"index\":");decimal(case_index++);field("file_size",file_size);status_field("section_protection",section_protection);status_field("view_protection",view_protection);field("grow",grow);status_field("create_a",create_a);status_field("create_b",create_b);
  text(",\"map_statuses\":[");for(unsigned i=0;i<4;++i){if(i)text(",");integer(static_cast<ULONG>(statuses[i]));}text("],\"view_sizes\":[");for(unsigned i=0;i<4;++i){if(i)text(",");decimal(sizes[i]);}text("]");
  text(",\"phases\":[");for(unsigned phase=0;phase<7;++phase){if(phase)text(",");text("[");for(unsigned i=0;i<4;++i){if(i)text(",");integer(phases[phase][i]);}text("]");}text("],\"file_values\":[");for(unsigned i=0;i<5;++i){if(i)text(",");integer(file_values[i]);}text("]");
  status_field("write_exception",write_exception);status_field("cow_exception",cow_exception);status_field("growth_create",growth_create);status_field("growth_query",growth_query);text(",\"growth_basic_hex\":\"");hex(growth_basic,sizeof(growth_basic));text("\"");status_field("growth_map",growth_map);field("growth_size",growth_size);status_field("growth_first",growth_first);status_field("growth_last",growth_last);field("file_size_after",static_cast<ULONGLONG>(length.QuadPart));field("delete_with_live_views",deleted);field("delete_error",delete_error);field("exists_after_unmap",exists);
  text(",\"unmap_statuses\":[");for(unsigned i=0;i<4;++i){if(i)text(",");integer(static_cast<ULONG>(unmapped[i]));}text("]");field("handle_delta",handles_after-handles_before);text("}\n");flush();
}
extern "C" void entry() {
  output=GetStdHandle(STD_OUTPUT_HANDLE);HMODULE ntdll=GetModuleHandleW(L"ntdll.dll");
  create_section=reinterpret_cast<CreateSection>(GetProcAddress(ntdll,"NtCreateSection"));query_section=reinterpret_cast<QuerySection>(GetProcAddress(ntdll,"NtQuerySection"));map_section=reinterpret_cast<MapSection>(GetProcAddress(ntdll,"NtMapViewOfSection"));unmap_section=reinterpret_cast<UnmapSection>(GetProcAddress(ntdll,"NtUnmapViewOfSection"));if(!create_section||!query_section||!map_section||!unmap_section)ExitProcess(2);
  void *check=VirtualAlloc(nullptr,4096,MEM_RESERVE|MEM_COMMIT,PAGE_READONLY);if(!check)ExitProcess(40);ULONG seh=store(check,0x22);if(seh!=0xC0000005||!VirtualFree(check,0,MEM_RELEASE))ExitProcess(41);
  for(unsigned i=0;i<sizeof(seed);++i)seed[i]=static_cast<unsigned char>(0x11+i*13);
  text("{\"kind\":\"profile\",\"pointer_bytes\":");decimal(sizeof(void*));status_field("seh_preflight",seh);text("}\n");flush();
  const ULONG sizes[]={1,4096,65537},growth_sizes[]={1,4096},protections[]={2,4,8};
  for(ULONG size:sizes)for(ULONG protection:protections)for(ULONG view:protections)observe(size,protection,view,false);
  for(ULONG size:growth_sizes)for(ULONG protection:protections)for(ULONG view:protections)observe(size,protection,view,true);
  ExitProcess(0);
}
