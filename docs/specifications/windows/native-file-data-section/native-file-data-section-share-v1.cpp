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


static void observe(ULONG section_page,ULONG sharing,unsigned stage,ULONG access){
 wchar_t name[]=L"share-00000.bin";unsigned number=case_index;
 for(unsigned digit=0;digit<5;++digit){name[10-digit]=wchar_t(L'0'+number%10);number/=10;}
 if(GetFileAttributesW(name)!=INVALID_FILE_ATTRIBUTES)ExitProcess(11);
 HANDLE file=CreateFileW(name,GENERIC_READ|GENERIC_WRITE,sharing,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);if(file==INVALID_HANDLE_VALUE)ExitProcess(12);
 DWORD written=0;if(!WriteFile(file,seed,4096,&written,nullptr)||written!=4096)ExitProcess(13);
 HANDLE section=nullptr;LONG created=create_section(&section,0xF001F,nullptr,nullptr,section_page,0x08000000,file);if(created!=0||!section)ExitProcess(14);
 void *view=nullptr;SIZE_T size=0;LONGLONG offset=0;LONG mapped=static_cast<LONG>(0xDEADBEEF);
 if(stage!=0){mapped=map_section(section,GetCurrentProcess(),&view,0,0,&offset,&size,2,0,2);if(mapped!=0||!view)ExitProcess(15);}
 if(!CloseHandle(file))ExitProcess(16);
 if(stage==2){if(!CloseHandle(section))ExitProcess(17);section=nullptr;}
 SetLastError(0);HANDLE reopened=CreateFileW(name,access,7,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);DWORD error=reopened==INVALID_HANDLE_VALUE?GetLastError():0;
 if(reopened!=INVALID_HANDLE_VALUE&&!CloseHandle(reopened))ExitProcess(18);
 unsigned char read=0;SIZE_T bytes=0;ULONG value=view?(ReadProcessMemory(GetCurrentProcess(),view,&read,1,&bytes)&&bytes==1?read:0xFFFFFFFE):0xFFFFFFFF;
 if(view&&unmap_section(GetCurrentProcess(),view)!=0)ExitProcess(19);
 if(section&&!CloseHandle(section))ExitProcess(20);
 if(!DeleteFileW(name))ExitProcess(21);
 text("{\"kind\":\"case\",\"index\":");decimal(case_index++);status_field("section_protection",section_page);status_field("original_share",sharing);field("stage",stage);status_field("next_access",access);status_field("create_status",created);status_field("map_status",mapped);field("reopened",reopened!=INVALID_HANDLE_VALUE);field("error",error);status_field("view_byte",value);text("}\n");flush();
}
extern "C" void entry(){
 output=GetStdHandle(STD_OUTPUT_HANDLE);HMODULE ntdll=GetModuleHandleW(L"ntdll.dll");create_section=reinterpret_cast<CreateSection>(GetProcAddress(ntdll,"NtCreateSection"));map_section=reinterpret_cast<MapSection>(GetProcAddress(ntdll,"NtMapViewOfSection"));unmap_section=reinterpret_cast<UnmapSection>(GetProcAddress(ntdll,"NtUnmapViewOfSection"));if(!create_section||!map_section||!unmap_section)ExitProcess(2);
 for(unsigned i=0;i<4096;++i)seed[i]=0x11;
 text("{\"kind\":\"profile\",\"pointer_bytes\":");decimal(sizeof(void*));text("}\n");flush();
 const ULONG pages[]={2,4,8},shares[]={0,1,3,5,7},accesses[]={GENERIC_READ,GENERIC_WRITE,GENERIC_READ|GENERIC_WRITE};
 for(ULONG page:pages)for(ULONG share:shares)for(unsigned stage=0;stage<3;++stage)for(ULONG access:accesses)observe(page,share,stage,access);
 ExitProcess(0);
}
