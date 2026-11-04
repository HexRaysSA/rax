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


using ProtectMemory=LONG(NTAPI *)(HANDLE,void **,SIZE_T *,ULONG,ULONG *);
static ProtectMemory protect_memory;
static void observe(ULONG section_page,ULONG initial,ULONG requested) {
 wchar_t name[]=L"post-copy-00000.bin";unsigned number=case_index;
 for(unsigned digit=0;digit<5;++digit){name[14-digit]=wchar_t(L'0'+number%10);number/=10;}
 if(GetFileAttributesW(name)!=INVALID_FILE_ATTRIBUTES)ExitProcess(11);
 HANDLE file=CreateFileW(name,GENERIC_READ|GENERIC_WRITE,7,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);if(file==INVALID_HANDLE_VALUE)ExitProcess(12);
 DWORD written=0;if(!WriteFile(file,seed,4096,&written,nullptr)||written!=4096)ExitProcess(13);
 HANDLE section=nullptr;LONG created=create_section(&section,0xF001F,nullptr,nullptr,section_page,0x08000000,file);if(created!=0||!section)ExitProcess(14);
 void *view=nullptr;SIZE_T size=0;LONGLONG offset=0;LONG mapped=map_section(section,GetCurrentProcess(),&view,0,0,&offset,&size,2,0,initial);
 ULONG old_copy=0xA5A5A5A5,old=old_copy;LONG first=static_cast<LONG>(0xDEADBEEF),changed=first;MEMORY_BASIC_INFORMATION before,after;memset(&before,0,sizeof(before));memset(&after,0,sizeof(after));ULONG byte=0xFFFFFFFF;
 if(mapped==0&&view){
  void *base=view;SIZE_T count=4096;first=protect_memory(GetCurrentProcess(),&base,&count,8,&old_copy);if(first!=0)ExitProcess(15);
  *static_cast<volatile unsigned char *>(view)=0x33;
  if(!VirtualQuery(view,&before,sizeof(before)))ExitProcess(16);
  base=view;count=4096;changed=protect_memory(GetCurrentProcess(),&base,&count,requested,&old);
  if(!VirtualQuery(view,&after,sizeof(after)))ExitProcess(17);
  unsigned char read=0;SIZE_T bytes=0;byte=ReadProcessMemory(GetCurrentProcess(),view,&read,1,&bytes)&&bytes==1?read:0xFFFFFFFE;
  if(unmap_section(GetCurrentProcess(),view)!=0)ExitProcess(18);
 }
 LARGE_INTEGER zero;zero.QuadPart=0;if(!SetFilePointerEx(file,zero,nullptr,FILE_BEGIN))ExitProcess(19);unsigned char read=0;DWORD bytes=0;if(!ReadFile(file,&read,1,&bytes,nullptr)||bytes!=1)ExitProcess(20);
 if(!CloseHandle(section)||!CloseHandle(file)||!DeleteFileW(name))ExitProcess(21);
 text("{\"kind\":\"case\",\"index\":");decimal(case_index++);status_field("section_protection",section_page);status_field("initial_protection",initial);status_field("protection",requested);status_field("create_status",created);status_field("map_status",mapped);status_field("copy_status",first);status_field("copy_old",old_copy);status_field("before_protection",before.Protect);status_field("protect_status",changed);status_field("old",old);status_field("after_protection",after.Protect);status_field("view_byte",byte);status_field("file_byte",read);text("}\n");flush();
}
extern "C" void entry(){
 output=GetStdHandle(STD_OUTPUT_HANDLE);HMODULE ntdll=GetModuleHandleW(L"ntdll.dll");
 create_section=reinterpret_cast<CreateSection>(GetProcAddress(ntdll,"NtCreateSection"));map_section=reinterpret_cast<MapSection>(GetProcAddress(ntdll,"NtMapViewOfSection"));unmap_section=reinterpret_cast<UnmapSection>(GetProcAddress(ntdll,"NtUnmapViewOfSection"));protect_memory=reinterpret_cast<ProtectMemory>(GetProcAddress(ntdll,"NtProtectVirtualMemory"));if(!create_section||!map_section||!unmap_section||!protect_memory)ExitProcess(2);
 for(unsigned i=0;i<4096;++i)seed[i]=0x11;
 text("{\"kind\":\"profile\",\"pointer_bytes\":");decimal(sizeof(void *));text("}\n");flush();
 const ULONG sections[]={2,4,8},pages[]={1,2,4,8,0x10,0x20,0x40,0x80};
 for(ULONG section:sections)for(ULONG initial:sections)for(ULONG requested:pages)observe(section,initial,requested);
 ExitProcess(0);
}
