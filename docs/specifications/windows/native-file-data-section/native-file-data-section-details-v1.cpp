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
static void create_pointer(unsigned out_mode,unsigned maximum_mode,unsigned oa_mode,unsigned file_mode,ULONG protection) {
  reset_pages();
  auto out=reinterpret_cast<HANDLE *>(arena);
  auto maximum=reinterpret_cast<LONGLONG *>(arena+4096);
  auto oa=reinterpret_cast<Attributes *>(arena+8192);
  memset(oa,0,sizeof(*oa));oa->length=sizeof(*oa);
  *maximum=maximum_mode==2?1:maximum_mode==3?-1:0;
  switch(out_mode){case 1:out=nullptr;break;case 2:out=reinterpret_cast<HANDLE *>(1);break;case 3:permission(0,PAGE_NOACCESS);break;case 4:permission(0,PAGE_READONLY);break;case 5:permission(0,PAGE_READWRITE|PAGE_GUARD);break;case 6:out=reinterpret_cast<HANDLE *>(arena+1);break;}
  switch(maximum_mode){case 0:maximum=nullptr;break;case 4:maximum=reinterpret_cast<LONGLONG *>(1);break;case 5:maximum=reinterpret_cast<LONGLONG *>(arena+4097);break;case 6:permission(1,PAGE_NOACCESS);break;case 7:permission(1,PAGE_READWRITE|PAGE_GUARD);break;}
  switch(oa_mode){case 0:oa=nullptr;break;case 2:oa->length=0;break;case 3:oa=reinterpret_cast<Attributes *>(1);break;case 4:permission(2,PAGE_READWRITE|PAGE_GUARD);break;case 5:permission(2,PAGE_READONLY);break;}
  ULONG exception=0;DWORD before=0,after=0;GetProcessHandleCount(GetCurrentProcess(),&before);
  LONG status=create_call(out,oa,maximum,protection,files[file_mode],&exception);
  const ULONG out_page=page_protection(0),max_page=page_protection(1),oa_page=page_protection(2);
  permission(0,PAGE_READWRITE);permission(1,PAGE_READWRITE);permission(2,PAGE_READWRITE);
  HANDLE result=nullptr;if(out_mode!=1&&out_mode!=2)memcpy(&result,out,sizeof(result));
  DWORD flags;BOOL valid=result&&GetHandleInformation(result,&flags);if(valid)CloseHandle(result);
  GetProcessHandleCount(GetCurrentProcess(),&after);
  text("{\"kind\":\"create_pointer\",\"index\":");decimal(case_index++);field("out_mode",out_mode);field("maximum_mode",maximum_mode);field("oa_mode",oa_mode);field("file_mode",file_mode);status_field("protection",protection);status_field("status",status);status_field("exception",exception);status_field("out_page",out_page);status_field("maximum_page",max_page);status_field("oa_page",oa_page);field("handle_valid",valid);field("handle_delta",after-before);text(",\"maximum_after_hex\":\"");hex(arena+4096,8);text("\"}\n");flush();
}
static LONG map_call(HANDLE section,void **base,ULONG_PTR zero,SIZE_T commit,LONGLONG *offset,SIZE_T *size,ULONG inherit,ULONG flags,ULONG protection,ULONG *exception) {
  LONG status=static_cast<LONG>(0xDEADBEEF);
  __try{status=map_section(section,GetCurrentProcess(),base,zero,commit,offset,size,inherit,flags,protection);}
  __except(EXCEPTION_EXECUTE_HANDLER){*exception=GetExceptionCode();}
  return status;
}
static void map_case(HANDLE section,ULONG section_protection,unsigned category,ULONGLONG value,ULONG view_protection=2) {
  reset_pages();auto base=reinterpret_cast<void **>(arena);auto size=reinterpret_cast<SIZE_T *>(arena+4096);auto offset=reinterpret_cast<LONGLONG *>(arena+8192);
  *base=nullptr;*size=0;*offset=0;ULONG_PTR zero=0;SIZE_T commit=0;ULONG inherit=2,flags=0;
  if(category==0)view_protection=static_cast<ULONG>(value);
  if(category==1)*size=static_cast<SIZE_T>(value);
  if(category==2)*offset=static_cast<LONGLONG>(value);
  if(category==3)zero=static_cast<ULONG_PTR>(value);
  if(category==4)commit=static_cast<SIZE_T>(value);
  if(category==5)inherit=static_cast<ULONG>(value);
  if(category==6)flags=static_cast<ULONG>(value);
  if(category==7)*base=reinterpret_cast<void *>(static_cast<ULONG_PTR>(value));
  if(category==8){switch(static_cast<unsigned>(value)){
    case 1:base=nullptr;break;case 2:base=reinterpret_cast<void **>(1);break;
    case 3:permission(0,PAGE_NOACCESS);break;case 4:permission(0,PAGE_READONLY);break;case 5:permission(0,PAGE_READWRITE|PAGE_GUARD);break;
    case 6:size=nullptr;break;case 7:size=reinterpret_cast<SIZE_T *>(1);break;
    case 8:permission(1,PAGE_NOACCESS);break;case 9:permission(1,PAGE_READONLY);break;case 10:permission(1,PAGE_READWRITE|PAGE_GUARD);break;
    case 11:offset=reinterpret_cast<LONGLONG *>(1);break;case 12:offset=reinterpret_cast<LONGLONG *>(arena+8193);break;
    case 13:permission(2,PAGE_NOACCESS);break;case 14:permission(2,PAGE_READONLY);break;case 15:permission(2,PAGE_READWRITE|PAGE_GUARD);break;
  }}
  ULONG exception=0;LONG status=map_call(section,base,zero,commit,offset,size,inherit,flags,view_protection,&exception);
  const ULONG base_page=page_protection(0),size_page=page_protection(1),offset_page=page_protection(2);
  permission(0,PAGE_READWRITE);permission(1,PAGE_READWRITE);permission(2,PAGE_READWRITE);
  void *result=nullptr;SIZE_T result_size=0;LONGLONG result_offset=0;
  if(base&&base!=reinterpret_cast<void **>(1))memcpy(&result,base,sizeof(result));
  if(size&&size!=reinterpret_cast<SIZE_T *>(1))memcpy(&result_size,size,sizeof(result_size));
  if(offset!=reinterpret_cast<LONGLONG *>(1))memcpy(&result_offset,offset,sizeof(result_offset));
  MEMORY_BASIC_INFORMATION region;memset(&region,0,sizeof(region));
  SIZE_T region_bytes=0;LONG unmapped=static_cast<LONG>(0xDEADBEEF);
  if(status>=0&&exception==0&&result){region_bytes=VirtualQuery(result,&region,sizeof(region));unmapped=unmap_section(GetCurrentProcess(),result);}
  text("{\"kind\":\"map\",\"index\":");decimal(case_index++);status_field("section_protection",section_protection);field("category",category);text(",\"value_hex\":\"");hex(&value,8);text("\"");status_field("protection",view_protection);status_field("status",status);status_field("exception",exception);status_field("base_page",base_page);status_field("size_page",size_page);status_field("offset_page",offset_page);text(",\"size_hex\":\"");hex(&result_size,sizeof(result_size));text("\",\"offset_hex\":\"");hex(&result_offset,8);text("\"");field("base_null",result==nullptr);field("region_return_bytes",region_bytes);status_field("region_protection",region.Protect);status_field("region_allocation_protection",region.AllocationProtect);status_field("region_type",region.Type);status_field("region_state",region.State);field("region_size",region.RegionSize);status_field("unmap_status",unmapped);text("}\n");flush();
}
static void protect_case(HANDLE section,ULONG section_protection,ULONG initial,ULONG protection) {
  void *base=nullptr;SIZE_T size=0;LONGLONG offset=0;
  LONG mapped=map_section(section,GetCurrentProcess(),&base,0,0,&offset,&size,2,0,initial);
  DWORD old=0xA5A5A5A5,error=0;BOOL changed=FALSE;ULONG exception=0xDEADBEEF;MEMORY_BASIC_INFORMATION region;memset(&region,0,sizeof(region));
  if(mapped>=0&&base){SetLastError(0);changed=VirtualProtect(base,4096,protection,&old);error=GetLastError();if(changed)exception=store(base,0x77);VirtualQuery(base,&region,sizeof(region));if(unmap_section(GetCurrentProcess(),base)!=0)ExitProcess(74);}
  text("{\"kind\":\"protect\",\"index\":");decimal(case_index++);status_field("section_protection",section_protection);status_field("initial_protection",initial);status_field("protection",protection);status_field("map_status",mapped);field("changed",changed);field("error",error);status_field("old",old);status_field("write_exception",exception);status_field("reported_protection",region.Protect);text("}\n");flush();
}
static LONG query_call(HANDLE section,ULONG klass,void *buffer,SIZE_T bytes,SIZE_T *returned,ULONG *exception) {
  LONG status=static_cast<LONG>(0xDEADBEEF);
  __try{status=query_section(section,klass,buffer,bytes,returned);}
  __except(EXCEPTION_EXECUTE_HANDLER){*exception=GetExceptionCode();}
  return status;
}
static void query_case(HANDLE section,unsigned mode,unsigned klass,unsigned bytes) {
  reset_pages();void *buffer=arena;auto returned=reinterpret_cast<SIZE_T *>(arena+4096);
  switch(mode){case 1:buffer=nullptr;break;case 2:buffer=reinterpret_cast<void *>(1);break;case 3:permission(0,PAGE_NOACCESS);break;case 4:permission(0,PAGE_READONLY);break;case 5:permission(0,PAGE_READWRITE|PAGE_GUARD);break;case 6:buffer=arena+1;break;case 7:returned=nullptr;break;case 8:returned=reinterpret_cast<SIZE_T *>(1);break;case 9:permission(1,PAGE_READONLY);break;case 10:permission(1,PAGE_READWRITE|PAGE_GUARD);break;}
  ULONG exception=0;LONG status=query_call(section,klass,buffer,bytes,returned,&exception);
  const ULONG data_page=page_protection(0),return_page=page_protection(1);
  permission(0,PAGE_READWRITE);permission(1,PAGE_READWRITE);
  text("{\"kind\":\"query\",\"index\":");decimal(case_index++);field("mode",mode);field("class",klass);field("bytes",bytes);status_field("status",status);status_field("exception",exception);status_field("data_page",data_page);status_field("return_page",return_page);text(",\"data_hex\":\"");hex(arena,40);text("\",\"return_hex\":\"");hex(arena+4096,sizeof(SIZE_T));text("\"}\n");flush();
}
extern "C" void entry() {
  output=GetStdHandle(STD_OUTPUT_HANDLE);HMODULE ntdll=GetModuleHandleW(L"ntdll.dll");
  create_section=reinterpret_cast<CreateSection>(GetProcAddress(ntdll,"NtCreateSection"));query_section=reinterpret_cast<QuerySection>(GetProcAddress(ntdll,"NtQuerySection"));map_section=reinterpret_cast<MapSection>(GetProcAddress(ntdll,"NtMapViewOfSection"));unmap_section=reinterpret_cast<UnmapSection>(GetProcAddress(ntdll,"NtUnmapViewOfSection"));
  if(!create_section||!query_section||!map_section||!unmap_section)ExitProcess(2);
  arena=static_cast<unsigned char *>(VirtualAlloc(nullptr,4*4096,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE));if(!arena)ExitProcess(3);
  void *check=VirtualAlloc(nullptr,4096,MEM_RESERVE|MEM_COMMIT,PAGE_READONLY);if(!check)ExitProcess(4);ULONG seh=store(check,0x22);if(seh!=0xC0000005||!VirtualFree(check,0,MEM_RELEASE))ExitProcess(5);
  const wchar_t *name=L"details-owned-file.bin";if(GetFileAttributesW(name)!=INVALID_FILE_ATTRIBUTES)ExitProcess(6);
  HANDLE writer=CreateFileW(name,GENERIC_READ|GENERIC_WRITE,7,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);if(writer==INVALID_HANDLE_VALUE)ExitProcess(7);
  change_file(writer,0,0x11);change_file(writer,65536,0x66);CloseHandle(writer);
  files[0]=CreateFileW(name,GENERIC_READ,7,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);files[1]=CreateFileW(name,GENERIC_READ|GENERIC_WRITE,7,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);if(files[0]==INVALID_HANDLE_VALUE||files[1]==INVALID_HANDLE_VALUE)ExitProcess(8);
  text("{\"kind\":\"profile\",\"pointer_bytes\":");decimal(sizeof(void *));status_field("seh_preflight",seh);text("}\n");flush();
  const ULONG constructor_protections[]={2,4},section_protections[]={2,4,8},pointer_protections[]={2,3};const unsigned query_sizes[]={0,1,15,16,23,24,32};
  for(unsigned out=0;out<7;++out)for(unsigned maximum=0;maximum<8;++maximum)for(unsigned oa=0;oa<6;++oa)for(unsigned file=0;file<2;++file)for(ULONG protection:constructor_protections)create_pointer(out,maximum,oa,file,protection);
  const ULONG protections[]={1,2,4,8,0x10,0x20,0x40,0x80,0,3,0x102,0x202,0x402};
  const ULONGLONG values[][13]={
    {1,2,4,8,0x10,0x20,0x40,0x80,0,3,0x102,0x202,0x402},
    {0,1,4095,4096,65536,65537,69632,69633,131072,0xFFFFFFFF},
    {0,1,4096,65535,65536,65537,131072,0xFFFFFFFFFFFFFFFFULL},
    {0,1,16,21,31,32,33,63,64,0xFFFFFFFF},
    {0,1,4096,65537,69632,69633},
    {0,1,2,3},
    {0,1,2,0x100000,0x400000,0x500000,0x800000,0x20000000,0x80000000,0x2000,0x4000},
    {0,1,4096,65536,0x50000000,0x50001000,0xFFFFFFFF}
  };const unsigned counts[]={13,10,8,10,6,4,11,7};
  for(ULONG protection:section_protections){
    HANDLE section=nullptr;if(create_section(&section,0xF001F,nullptr,nullptr,protection,0x08000000,files[1])!=0||!section)ExitProcess(9);
    for(unsigned category=0;category<8;++category)for(unsigned i=0;i<counts[category];++i)map_case(section,protection,category,values[category][i]);
    for(unsigned mode=0;mode<16;++mode)for(ULONG page:pointer_protections)map_case(section,protection,8,mode,page);
    for(ULONG initial:section_protections)for(unsigned i=0;i<8;++i)protect_case(section,protection,initial,protections[i]);
    if(protection==2)for(unsigned klass=0;klass<3;++klass)for(unsigned mode=0;mode<11;++mode)for(unsigned size:query_sizes)query_case(section,mode,klass,size);
    CloseHandle(section);
  }
  CloseHandle(files[0]);CloseHandle(files[1]);if(!DeleteFileW(name)||!VirtualFree(arena,0,MEM_RELEASE))ExitProcess(10);
  ExitProcess(0);
}
