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
static LONG invoke(HANDLE *section,LONGLONG *maximum,ULONG protection,ULONG attributes,HANDLE file,ULONG *exception) {
  LONG status=static_cast<LONG>(0xDEADBEEF);
  __try { status=create_section(section,0xF001F,nullptr,maximum,protection,attributes,file); }
  __except(EXCEPTION_EXECUTE_HANDLER) { *exception=GetExceptionCode(); }
  return status;
}
static void observe(unsigned group,ULONG file_size,unsigned mode,unsigned maximum_mode,ULONG protection,ULONG attributes) {
  wchar_t name[]=L"section-00000.bin";unsigned number=case_index;
  for(unsigned digit=0;digit<5;++digit){name[12-digit]=wchar_t(L'0'+number%10);number/=10;}
  if(GetFileAttributesW(name)!=INVALID_FILE_ATTRIBUTES)ExitProcess(10);
  HANDLE writer=CreateFileW(name,GENERIC_READ|GENERIC_WRITE,7,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);
  if(writer==INVALID_HANDLE_VALUE)ExitProcess(11);
  DWORD written=0;
  if(file_size&&(!WriteFile(writer,seed,file_size,&written,nullptr)||written!=file_size))ExitProcess(12);
  CloseHandle(writer);
  const ULONG file_access[]={GENERIC_READ,GENERIC_READ|GENERIC_WRITE,0,GENERIC_EXECUTE,GENERIC_READ|GENERIC_EXECUTE,GENERIC_ALL};
  HANDLE file=CreateFileW(name,file_access[mode],7,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
  if(file==INVALID_HANDLE_VALUE)ExitProcess(13);
  const LONGLONG maxima[]={0,0,1,4095,4096,65536,-1};LONGLONG maximum=maxima[maximum_mode];
  HANDLE section=reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(0xA5A5A5A5));ULONG exception=0;
  DWORD handles_before=0,handles_after=0;GetProcessHandleCount(GetCurrentProcess(),&handles_before);
  LONG status=invoke(&section,maximum_mode?&maximum:nullptr,protection,attributes,file,&exception);
  DWORD flags=0;BOOL valid=GetHandleInformation(section,&flags);
  alignas(8) unsigned char section_basic[24],object_basic[56],image_info[64];
  memset(section_basic,0xA5,sizeof(section_basic));memset(object_basic,0xA5,sizeof(object_basic));memset(image_info,0xA5,sizeof(image_info));
  SIZE_T basic_length=static_cast<SIZE_T>(0xA5A5A5A5),image_length=static_cast<SIZE_T>(0xA5A5A5A5);ULONG object_length=0;
  LONG basic_status=static_cast<LONG>(0xDEADBEEF),object_status=basic_status,image_status=basic_status,map_status=basic_status,unmap_status=basic_status;
  SIZE_T view_size=0,read_count=0,tail_count=0;void *base=nullptr;LONGLONG offset=0;
  unsigned char first[8],tail[8];memset(first,0xA5,sizeof(first));memset(tail,0xA5,sizeof(tail));
  MEMORY_BASIC_INFORMATION region;memset(&region,0xA5,sizeof(region));SIZE_T queried=0;DWORD read_error=0,tail_error=0;
  LARGE_INTEGER after_create,after_map;after_create.QuadPart=after_map.QuadPart=-1;
  if(!GetFileSizeEx(file,&after_create))ExitProcess(14);
  if(valid) {
    basic_status=query_section(section,0,section_basic,sizeof(section_basic),&basic_length);
    object_status=query_object(section,0,object_basic,sizeof(object_basic),&object_length);
    image_status=query_section(section,1,image_info,sizeof(image_info),&image_length);
    map_status=map_section(section,GetCurrentProcess(),&base,0,0,&offset,&view_size,2,0,protection);
    if(map_status>=0&&base) {
      queried=VirtualQuery(base,&region,sizeof(region));
      if(!ReadProcessMemory(GetCurrentProcess(),base,first,sizeof(first),&read_count))read_error=GetLastError();
      if(view_size>=8&&!ReadProcessMemory(GetCurrentProcess(),static_cast<unsigned char *>(base)+view_size-8,tail,sizeof(tail),&tail_count))tail_error=GetLastError();
      unmap_status=unmap_section(GetCurrentProcess(),base);
    }
    CloseHandle(section);
  }
  if(!GetFileSizeEx(file,&after_map))ExitProcess(15);
  GetProcessHandleCount(GetCurrentProcess(),&handles_after);
  text("{\"kind\":\"case\",\"index\":");decimal(case_index++);field("group",group);field("file_size",file_size);field("file_mode",mode);field("maximum_mode",maximum_mode);
  status_field("protection",protection);status_field("attributes",attributes);status_field("status",status);status_field("exception",exception);field("handle_valid",valid);
  status_field("section_basic_status",basic_status);field("section_basic_return_bytes",basic_length);text(",\"section_basic_hex\":\"");hex(section_basic,sizeof(section_basic));text("\"");
  status_field("object_basic_status",object_status);text(",\"object_basic_hex\":\"");hex(object_basic,sizeof(object_basic));text("\"");status_field("image_status",image_status);field("image_return_bytes",image_length);
  status_field("map_status",map_status);field("mapped",base!=nullptr&&map_status>=0);field("view_size",view_size);field("region_return_bytes",queried);
  if(queried){status_field("region_protection",region.Protect);status_field("region_allocation_protection",region.AllocationProtect);status_field("region_state",region.State);status_field("region_type",region.Type);field("region_size",region.RegionSize);}
  field("read_bytes",read_count);field("read_error",read_error);text(",\"first_hex\":\"");hex(first,sizeof(first));text("\"");field("tail_bytes",tail_count);field("tail_error",tail_error);text(",\"tail_hex\":\"");hex(tail,sizeof(tail));text("\"");
  status_field("unmap_status",unmap_status);field("size_after_create",static_cast<ULONGLONG>(after_create.QuadPart));field("size_after_map",static_cast<ULONGLONG>(after_map.QuadPart));field("handle_delta",handles_after-handles_before);text("}\n");flush();
  CloseHandle(file);if(!DeleteFileW(name))ExitProcess(16);
}
extern "C" void entry() {
  output=GetStdHandle(STD_OUTPUT_HANDLE);HMODULE ntdll=GetModuleHandleW(L"ntdll.dll");
  create_section=reinterpret_cast<CreateSection>(GetProcAddress(ntdll,"NtCreateSection"));query_section=reinterpret_cast<QuerySection>(GetProcAddress(ntdll,"NtQuerySection"));map_section=reinterpret_cast<MapSection>(GetProcAddress(ntdll,"NtMapViewOfSection"));unmap_section=reinterpret_cast<UnmapSection>(GetProcAddress(ntdll,"NtUnmapViewOfSection"));query_object=reinterpret_cast<QueryObject>(GetProcAddress(ntdll,"NtQueryObject"));
  if(!create_section||!query_section||!map_section||!unmap_section||!query_object)ExitProcess(2);
  for(unsigned i=0;i<sizeof(seed);++i)seed[i]=static_cast<unsigned char>(0x11+i*13);
  text("{\"kind\":\"profile\",\"pointer_bytes\":");decimal(sizeof(void*));field("memory_information_bytes",sizeof(MEMORY_BASIC_INFORMATION));text("}\n");flush();
  const ULONG sizes[]={0,1,4095,4096,52360},protections[]={2,4,8,0x10,0x20,0x40,0x80},allocations[]={0x08000000UL,0x04000000UL};
  for(ULONG size:sizes)for(unsigned mode=0;mode<2;++mode)for(unsigned maximum=0;maximum<7;++maximum)for(ULONG protection:protections)for(ULONG attributes:allocations)observe(0,size,mode,maximum,protection,attributes);
  for(unsigned mode=0;mode<6;++mode)for(ULONG protection:protections)observe(1,4096,mode,0,protection,0x08000000);
  const ULONG attributes[]={0,0x0C000000,0x18000000,0x48000000,0x88000000,0x08000001,0x08000080,0x08600000};
  for(unsigned mode=0;mode<2;++mode)for(ULONG protection:protections)for(ULONG flags:attributes)observe(2,4096,mode,0,protection,flags);
  ExitProcess(0);
}
