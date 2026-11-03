#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stddef.h>

struct Unicode { USHORT length, maximum; wchar_t *buffer; };
struct Attributes { ULONG length; HANDLE root; Unicode *name; ULONG flags; void *security, *qos; };
struct Io { ULONG_PTR status, information; };
using Create = LONG (NTAPI *)(HANDLE *,ULONG,Attributes *,Io *,LONGLONG *,ULONG,ULONG,ULONG,ULONG,void *,ULONG);
using QueryFile = LONG (NTAPI *)(HANDLE,Io *,void *,ULONG,ULONG);
using QueryObject = LONG (NTAPI *)(HANDLE,ULONG,void *,ULONG,ULONG *);
static HANDLE stream, root;
static Create create_file;
static QueryFile query_file;
static QueryObject query_object;
static unsigned index;
static volatile char line[16384];
static unsigned used;

extern "C" __declspec(noinline) void *memset(void *p,int value,size_t n) {
  auto b=static_cast<volatile unsigned char *>(p);for(size_t i=0;i<n;++i)b[i]=static_cast<unsigned char>(value);return p;
}
extern "C" __declspec(noinline) void *memcpy(void *p,const void *q,size_t n) {
  auto a=static_cast<volatile unsigned char *>(p);auto b=static_cast<const volatile unsigned char *>(q);for(size_t i=0;i<n;++i)a[i]=b[i];return p;
}
static void flush(){DWORD n=0;if(!WriteFile(stream,const_cast<const char *>(line),used,&n,nullptr)||n!=used)ExitProcess(90);used=0;}
static void text(const char *p){while(*p){if(used==sizeof(line))flush();line[used++]=*p++;}}
static void number(ULONG n){char b[16];unsigned p=sizeof(b);do{b[--p]=char('0'+n%10);n/=10;}while(n);while(p<sizeof(b)){char one[]={b[p++],0};text(one);}}
static void hex(const unsigned char *p,unsigned n){static const char d[]="0123456789ABCDEF";for(unsigned i=0;i<n;++i){char pair[]={d[p[i]>>4],d[p[i]&15],0};text(pair);}}
static void integer(ULONG n){unsigned char b[]={static_cast<unsigned char>(n>>24),static_cast<unsigned char>(n>>16),static_cast<unsigned char>(n>>8),static_cast<unsigned char>(n)};text("\"0x");hex(b,4);text("\"");}
static void wide_integer(ULONGLONG n){unsigned char b[8];for(unsigned i=0;i<8;++i)b[7-i]=static_cast<unsigned char>(n>>(8*i));text("\"0x");hex(b,8);text("\"");}
static LONG invoke(HANDLE *handle,ULONG access,Attributes *attrs,Io *io,LONGLONG *allocation,ULONG attributes,ULONG share,ULONG disposition,ULONG options,void *ea,ULONG ea_bytes,ULONG *exception){
  LONG result=static_cast<LONG>(0xDEADBEEF);
  __try { result=create_file(handle,access,attrs,io,allocation,attributes,share,disposition,options,ea,ea_bytes); }
  __except(EXCEPTION_EXECUTE_HANDLER){*exception=GetExceptionCode();}
  return result;
}
static wchar_t name[32];
static void case_name(unsigned n){const wchar_t prefix[]=L"case-00000.dat";memcpy(name,prefix,sizeof(prefix));for(unsigned i=0;i<5;++i){name[9-i]=wchar_t(L'0'+n%10);n/=10;}}
static void observe(unsigned group,bool existing,ULONG access,ULONG share,ULONG disposition,ULONG options,ULONG file_attributes,unsigned allocation_mode,unsigned ea_mode,unsigned held_mode=0){
  case_name(index);
  if(GetFileAttributesW(name)!=INVALID_FILE_ATTRIBUTES)ExitProcess(11);
  if(existing){HANDLE h=CreateFileW(name,GENERIC_WRITE,7,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);if(h==INVALID_HANDLE_VALUE)ExitProcess(12);DWORD n=0;if(!WriteFile(h,"original",8,&n,nullptr)||n!=8)ExitProcess(13);CloseHandle(h);}
  HANDLE held=INVALID_HANDLE_VALUE;
  if(held_mode){held=CreateFileW(name,GENERIC_READ,held_mode==1?FILE_SHARE_READ:0,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);if(held==INVALID_HANDLE_VALUE)ExitProcess(14);}
  Unicode unicode;unicode.length=28;unicode.maximum=30;unicode.buffer=name;
  Attributes attrs;attrs.length=sizeof(attrs);attrs.root=root;attrs.name=&unicode;attrs.flags=0x40;attrs.security=nullptr;attrs.qos=nullptr;
  HANDLE handle=reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(0xA5A5A5A5));
  Io io;memset(&io,0xA5,sizeof(io));
  LONGLONG allocation_value=allocation_mode==2?-1:allocation_mode==3?1:allocation_mode==4?4096:allocation_mode==5?65536:0;
  LONGLONG *allocation=allocation_mode?&allocation_value:nullptr;
  if(allocation_mode==6)allocation=reinterpret_cast<LONGLONG *>(1);
  unsigned char ea[32];memset(ea,0,sizeof(ea));ea[5]=3;ea[6]=2;ea[8]='O';ea[9]='n';ea[10]='e';ea[12]=0x12;ea[13]=0x34;
  void *ea_buffer=ea_mode?ea:nullptr;ULONG ea_bytes=ea_mode==1?14:ea_mode==2?1:ea_mode==3?32:ea_mode==4?14:0;
  if(ea_mode==4)ea_buffer=nullptr;
  DWORD handles_before=0,handles_after=0;GetProcessHandleCount(GetCurrentProcess(),&handles_before);
  ULONG exception=0;LONG status=invoke(&handle,access,&attrs,&io,allocation,file_attributes,share,disposition,options,ea_buffer,ea_bytes,&exception);
  DWORD handle_flags=0;BOOL valid=GetHandleInformation(handle,&handle_flags);
  ULONG granted=0,returned=0;LONG grant_status=static_cast<LONG>(0xDEADBEEF),standard_status=static_cast<LONG>(0xDEADBEEF);
  alignas(8) unsigned char basic[56],standard[24];memset(basic,0xA5,sizeof(basic));memset(standard,0xA5,sizeof(standard));Io query_io;memset(&query_io,0,sizeof(query_io));
  if(valid){grant_status=query_object(handle,0,basic,sizeof(basic),&returned);memcpy(&granted,basic+4,4);standard_status=query_file(handle,&query_io,standard,sizeof(standard),5);CloseHandle(handle);}
  if(held!=INVALID_HANDLE_VALUE)CloseHandle(held);
  GetProcessHandleCount(GetCurrentProcess(),&handles_after);
  WIN32_FILE_ATTRIBUTE_DATA after;memset(&after,0,sizeof(after));BOOL exists=GetFileAttributesExW(name,GetFileExInfoStandard,&after);DWORD metadata_error=exists?0:GetLastError();
  unsigned char contents[8];memset(contents,0xA5,sizeof(contents));DWORD bytes=0,read_error=0;
  if(exists&&(after.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)==0){HANDLE h=CreateFileW(name,GENERIC_READ,7,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);if(h!=INVALID_HANDLE_VALUE){if(!ReadFile(h,contents,sizeof(contents),&bytes,nullptr))read_error=GetLastError();CloseHandle(h);}else read_error=GetLastError();}
  text("{\"kind\":\"case\",\"index\":");number(index++);text(",\"group\":");number(group);text(",\"existing\":");number(existing);text(",\"access\":");integer(access);text(",\"share\":");number(share);text(",\"disposition\":");number(disposition);text(",\"options\":");integer(options);text(",\"attributes\":");integer(file_attributes);text(",\"allocation_mode\":");number(allocation_mode);text(",\"ea_mode\":");number(ea_mode);text(",\"held_mode\":");number(held_mode);
  text(",\"status\":");integer(static_cast<ULONG>(status));text(",\"exception\":");integer(exception);text(",\"handle_valid\":");number(valid);text(",\"handle\":");wide_integer(reinterpret_cast<ULONG_PTR>(handle));text(",\"io_hex\":\"");hex(reinterpret_cast<const unsigned char *>(&io),sizeof(io));text("\",\"grant_status\":");integer(static_cast<ULONG>(grant_status));text(",\"granted\":");integer(granted);text(",\"standard_status\":");integer(static_cast<ULONG>(standard_status));text(",\"standard_hex\":\"");hex(standard,sizeof(standard));text("\",\"handle_delta\":");number(handles_after-handles_before+(held_mode?1:0));
  text(",\"exists_after_close\":");number(exists);text(",\"metadata_error\":");number(metadata_error);text(",\"attributes_after\":");integer(after.dwFileAttributes);text(",\"size_after\":");wide_integer((static_cast<ULONGLONG>(after.nFileSizeHigh)<<32)|after.nFileSizeLow);text(",\"read_error\":");number(read_error);text(",\"read_bytes\":");number(bytes);text(",\"data_hex\":\"");hex(contents,bytes);text("\"}\n");flush();
  if(exists){SetFileAttributesW(name,FILE_ATTRIBUTE_NORMAL);if(after.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY){if(!RemoveDirectoryW(name))ExitProcess(15);}else if(!DeleteFileW(name))ExitProcess(16);}
}
extern "C" void entry(){
  stream=GetStdHandle(STD_OUTPUT_HANDLE);HMODULE ntdll=GetModuleHandleW(L"ntdll.dll");create_file=reinterpret_cast<Create>(GetProcAddress(ntdll,"NtCreateFile"));query_file=reinterpret_cast<QueryFile>(GetProcAddress(ntdll,"NtQueryInformationFile"));query_object=reinterpret_cast<QueryObject>(GetProcAddress(ntdll,"NtQueryObject"));if(!create_file||!query_file||!query_object)ExitProcess(2);
  root=CreateFileW(L".",GENERIC_READ|GENERIC_WRITE,7,nullptr,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS,nullptr);if(root==INVALID_HANDLE_VALUE)ExitProcess(3);
  text("{\"kind\":\"profile\",\"pointer_bytes\":");number(sizeof(void*));text(",\"attributes_bytes\":");number(sizeof(Attributes));text(",\"io_bytes\":");number(sizeof(Io));text("}\n");flush();
  const ULONG access[]={0,0x80100080,0x40100080,0xC0100080,0x00010000,0x02000000,0x001F01FF,0x00100000,0x00000080};
  const ULONG options[]={0,0x20,0x60,0x20060,0x21,0x61,0x1060,0xFFFFFFFF};
  for(unsigned exists=0;exists<2;++exists)for(ULONG disposition=0;disposition<8;++disposition)for(ULONG a:access)observe(0,exists!=0,a,7,disposition,0x60,0,0,0);
  for(unsigned exists=0;exists<2;++exists)for(ULONG disposition=0;disposition<6;++disposition)for(ULONG o:options)observe(1,exists!=0,0xC0100080,7,disposition,o,0,0,0);
  const ULONG attributes[]={0,0x80,1,2,4,0x20,0x100,0xFFFFFFFF};
  for(unsigned exists=0;exists<2;++exists)for(ULONG disposition=0;disposition<6;++disposition)for(ULONG a:attributes)observe(2,exists!=0,0xC0100080,7,disposition,0x60,a,0,0);
  for(unsigned exists=0;exists<2;++exists)for(ULONG disposition=0;disposition<6;++disposition)for(unsigned a=0;a<7;++a)observe(3,exists!=0,0xC0100080,7,disposition,0x60,0,a,0);
  for(unsigned exists=0;exists<2;++exists)for(ULONG disposition=0;disposition<6;++disposition)for(unsigned e=0;e<5;++e)observe(4,exists!=0,0xC0100080,7,disposition,0x60,0,0,e);
  for(unsigned held=1;held<=2;++held)for(ULONG disposition=0;disposition<6;++disposition)observe(5,true,0xC0100080,7,disposition,0x60,0,0,0,held);
  CloseHandle(root);ExitProcess(0);
}
