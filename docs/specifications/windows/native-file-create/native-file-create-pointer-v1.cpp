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
static unsigned char *arena,*before;
static void protect(unsigned page,DWORD flags){DWORD old=0;if(!VirtualProtect(arena+page*4096,4096,flags,&old))ExitProcess(20);}
static unsigned offset(unsigned field,unsigned size,unsigned role){return field*8192+(role>=7&&role<=9?4096-size/2:128+(role==2?1:0));}
static unsigned char *pointer(unsigned field,unsigned size,unsigned role){return role==1?nullptr:role==10?reinterpret_cast<unsigned char *>(1):arena+offset(field,size,role);}
static ULONG_PTR read_pointer(const unsigned char *p){ULONG_PTR n=0;for(unsigned i=0;i<sizeof(void*);++i)n|=static_cast<ULONG_PTR>(p[i])<<(8*i);return n;}
static void protection(unsigned field,unsigned role){unsigned page=field*2;if(role==3)protect(page,PAGE_READONLY);if(role==4)protect(page,PAGE_NOACCESS);if(role==5)protect(page,PAGE_READWRITE|PAGE_GUARD);if(role==6)protect(page,PAGE_READONLY|PAGE_GUARD);if(role==7)protect(page+1,PAGE_NOACCESS);if(role==8)protect(page+1,PAGE_READONLY);if(role==9)protect(page+1,PAGE_READWRITE|PAGE_GUARD);}
static void observe(const unsigned roles[8],unsigned parameter=0,unsigned alias=0){
  for(unsigned i=0;i<16;++i)protect(i,PAGE_READWRITE);memset(arena,0xA5,65536);case_name(index);
  HANDLE seeded=CreateFileW(name,GENERIC_WRITE,7,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);if(seeded==INVALID_HANDLE_VALUE)ExitProcess(11);DWORD written=0;if(!WriteFile(seeded,"original",8,&written,nullptr)||written!=8)ExitProcess(12);CloseHandle(seeded);
  const unsigned sizes[]={sizeof(void*),sizeof(Attributes),sizeof(Io),8,sizeof(Unicode),30,14,12};
  unsigned char *p[8];for(unsigned i=0;i<8;++i)p[i]=pointer(i,sizes[i],roles[i]);
  if(alias==1)p[0]=p[2];if(alias==2)p[0]=p[2]+sizeof(void*);if(alias==3)p[2]=p[0]+4;if(alias==4)p[2]=p[0]-4;
  unsigned placement[8];for(unsigned i=0;i<8;++i)placement[i]=offset(i,sizes[i],roles[i]==1||roles[i]==10?0:roles[i]);
  Attributes attrs;memset(&attrs,0,sizeof(attrs));attrs.length=sizeof(Attributes);attrs.root=root;attrs.name=reinterpret_cast<Unicode *>(p[4]);attrs.flags=0x40;attrs.qos=p[7];
  if(parameter==8)attrs.length=0;memcpy(arena+placement[1],&attrs,sizeof(attrs));
  Unicode unicode;memset(&unicode,0,sizeof(unicode));unicode.length=28;unicode.maximum=30;unicode.buffer=reinterpret_cast<wchar_t *>(p[5]);memcpy(arena+placement[4],&unicode,sizeof(unicode));memcpy(arena+placement[5],name,30);
  LONGLONG allocation=parameter==5?-1:0;memcpy(arena+placement[3],&allocation,8);
  auto ea=arena+placement[6];memset(ea,0,14);ea[5]=3;ea[6]=2;ea[8]='O';ea[9]='n';ea[10]='e';ea[12]=0x12;ea[13]=0x34;
  auto qos=arena+placement[7];memset(qos,0,12);qos[0]=12;qos[4]=2;qos[8]=1;qos[9]=1;
  ULONG access=parameter==4?0x04000000:0x80100080,share=parameter==2?8:7,disposition=parameter==1?6:1,options=parameter==3?0x30:0x20060,attributes=parameter==7?0xFFFFFFFF:0,ea_bytes=parameter==6?1:14;
  memcpy(before,arena,65536);for(unsigned i=0;i<8;++i)protection(i,roles[i]);
  DWORD handles_before=0,handles_after=0;GetProcessHandleCount(GetCurrentProcess(),&handles_before);ULONG exception=0;
  LONG status=invoke(reinterpret_cast<HANDLE *>(p[0]),access,reinterpret_cast<Attributes *>(p[1]),reinterpret_cast<Io *>(p[2]),reinterpret_cast<LONGLONG *>(p[3]),attributes,share,disposition,options,p[6],ea_bytes,&exception);
  DWORD protections[16];for(unsigned i=0;i<16;++i){MEMORY_BASIC_INFORMATION info;if(!VirtualQuery(arena+4096*i,&info,sizeof(info)))ExitProcess(21);protections[i]=info.Protect;protect(i,PAGE_READWRITE);}
  HANDLE handle=nullptr;BOOL valid=FALSE;DWORD hf=0;ULONG_PTR out_address=reinterpret_cast<ULONG_PTR>(p[0]),base=reinterpret_cast<ULONG_PTR>(arena);
  if(out_address>=base&&out_address-base<=65536-sizeof(void*)){handle=reinterpret_cast<HANDLE>(read_pointer(p[0]));if(read_pointer(before+(out_address-base))!=reinterpret_cast<ULONG_PTR>(handle)&&handle!=root)valid=GetHandleInformation(handle,&hf);}
  if(valid)CloseHandle(handle);GetProcessHandleCount(GetCurrentProcess(),&handles_after);
  WIN32_FILE_ATTRIBUTE_DATA info;memset(&info,0,sizeof(info));BOOL exists=GetFileAttributesExW(name,GetFileExInfoStandard,&info);
  text("{\"kind\":\"case\",\"index\":");number(index++);text(",\"roles\":[");for(unsigned i=0;i<8;++i){if(i)text(",");number(roles[i]);}text("],\"parameter\":");number(parameter);text(",\"alias\":");number(alias);text(",\"status\":");integer(static_cast<ULONG>(status));text(",\"exception\":");integer(exception);text(",\"handle_valid\":");number(valid);text(",\"output\":");wide_integer(reinterpret_cast<ULONG_PTR>(handle));text(",\"handle_delta\":");number(handles_after-handles_before);text(",\"exists\":");number(exists);text(",\"file_size\":");wide_integer((static_cast<ULONGLONG>(info.nFileSizeHigh)<<32)|info.nFileSizeLow);text(",\"protections\":[");for(unsigned i=0;i<16;++i){if(i)text(",");number(protections[i]);}text("],\"changes\":[");
  bool comma=false;unsigned at=0;while(at<65536){if(arena[at]==before[at]){++at;continue;}unsigned start=at;while(at<65536&&arena[at]!=before[at])++at;if(comma)text(",");comma=true;text("[");number(start);text(",\"");hex(arena+start,at-start);text("\"]");}text("]}\n");flush();
  if(exists){SetFileAttributesW(name,FILE_ATTRIBUTE_NORMAL);if(!DeleteFileW(name))ExitProcess(22);}
}
extern "C" void entry(){
  stream=GetStdHandle(STD_OUTPUT_HANDLE);HMODULE ntdll=GetModuleHandleW(L"ntdll.dll");create_file=reinterpret_cast<Create>(GetProcAddress(ntdll,"NtCreateFile"));if(!create_file)ExitProcess(2);
  root=CreateFileW(L".",GENERIC_READ|GENERIC_WRITE,7,nullptr,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS,nullptr);if(root==INVALID_HANDLE_VALUE)ExitProcess(3);
  constexpr ULONG_PTR base=sizeof(void*)==8?static_cast<ULONG_PTR>(0x100000000ULL):static_cast<ULONG_PTR>(0x30000000);
  arena=static_cast<unsigned char *>(VirtualAlloc(reinterpret_cast<void *>(base),65536,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE));before=static_cast<unsigned char *>(VirtualAlloc(nullptr,65536,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE));if(reinterpret_cast<ULONG_PTR>(arena)!=base||!before)ExitProcess(4);
  text("{\"kind\":\"profile\",\"pointer_bytes\":");number(sizeof(void*));text(",\"base\":");wide_integer(base);text(",\"root_handle\":");wide_integer(reinterpret_cast<ULONG_PTR>(root));text("}\n");flush();
  unsigned roles[8]={0,0,0,0,0,0,0,0};observe(roles);
  for(unsigned field=0;field<8;++field)for(unsigned role=1;role<=10;++role){roles[field]=role;observe(roles);roles[field]=0;}
  for(unsigned a=1;a<=10;++a)for(unsigned b=1;b<=10;++b){roles[0]=a;roles[2]=b;observe(roles);}roles[0]=roles[2]=0;
  const unsigned fields[]={1,3,4,5,6,7},input_roles[]={4,5,7},output_roles[]={3,5,7};for(unsigned field:fields)for(unsigned in:input_roles)for(unsigned out:output_roles){roles[field]=in;roles[0]=out;observe(roles);roles[field]=0;roles[0]=0;}
  for(unsigned parameter=1;parameter<=8;++parameter)for(unsigned field=0;field<8;++field)for(unsigned role=4;role<=5;++role){roles[field]=role;observe(roles,parameter);roles[field]=0;}
  for(unsigned alias=1;alias<=4;++alias)observe(roles,0,alias);
  CloseHandle(root);VirtualFree(arena,0,MEM_RELEASE);VirtualFree(before,0,MEM_RELEASE);ExitProcess(0);
}
