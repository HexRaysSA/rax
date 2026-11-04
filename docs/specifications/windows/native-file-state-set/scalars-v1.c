#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include "runtime-v1.h"

typedef struct IoStatus {
  union { LONG status; void *pointer; } result;
  ULONG_PTR information;
} IoStatus;
typedef LONG (NTAPI *InformationFn)(HANDLE,IoStatus *,void *,ULONG,ULONG);
typedef struct Resource {
  HANDLE handle, parent, independent;
  HANDLE owned[5]; unsigned count;
  BOOL file, directory;
} Resource;
static InformationFn query_file,set_file;
static const char *roles[]={"file.sync.rw","file.sync.read","file.sync.attributes",
  "file.async.rw","file.duplicate.attributes","directory.read","null.rw",
  "console.in","console.out","pipe.read","pipe.write","event","invalid",
  "process.pseudo","thread.pseudo","file.no-buffering","file.async.attributes",
  "file.write-through","file.sequential","file.delete-on-close"};
static const unsigned lengths[]={0,1,3,4,7,8,16,64};
static const uint64_t positions[]={0,1,7,37,511,512,513,1024,4095,4096,0x7FFFFFFFULL,0x80000000ULL,
  0x100000000ULL,0x7FFFFFFFFFFFFFFFULL,0xFFFFFFFFFFFFFFFFULL,
  0xFFFFFFFFFFFFFFFEULL,0xFFFFFFFFFFFFFFFDULL,0x8000000000000000ULL};
static const uint64_t modes[]={0,1,2,3,4,8,0x10,0x20,0x21,0x22,0x24,0x28,
  0x30,0x32,0x1000,0x103E,0xFFFFFFFFULL};
static const uint64_t notifications[]={0,1,2,3,4,5,6,7,8,16,0xFFFFFFFFULL};
static const uint64_t priorities[]={0,1,2,3,4,5,0xFFFFFFFFULL};

static void hex(const void *data,size_t bytes) {
  const unsigned char *p=data;control_char('"');
  for(size_t i=0;i<bytes;++i)control_print("%02x",(unsigned)p[i]);
  control_char('"');
}
static HANDLE keep(Resource *r,HANDLE h) {
  if(h==NULL||h==INVALID_HANDLE_VALUE||r->count==5)ExitProcess(20);
  r->owned[r->count++]=h;return h;
}
static HANDLE opened(DWORD access,DWORD flags) {
  return CreateFileW(L"state-v1.bin",access,7,NULL,OPEN_EXISTING,flags,NULL);
}
static Resource acquire(unsigned role) {
  Resource r;memset(&r,0,sizeof r);
  if(role<=4||role>=15) {
    r.file=TRUE;
    HANDLE base=keep(&r,CreateFileW(L"state-v1.bin",GENERIC_READ|GENERIC_WRITE,7,
      NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL));
    static const char payload[]="native file-state setter control data";
    DWORD written;if(!WriteFile(base,payload,sizeof payload-1,&written,NULL)||
      written!=sizeof payload-1||SetFilePointer(base,7,NULL,FILE_BEGIN)!=7)ExitProcess(21);
    r.parent=base;
    switch(role) {
      case 0:r.handle=base;break;
      case 1:r.handle=keep(&r,opened(GENERIC_READ,0));break;
      case 2:r.handle=keep(&r,opened(FILE_READ_ATTRIBUTES,0));break;
      case 3:r.handle=keep(&r,opened(GENERIC_READ|GENERIC_WRITE,FILE_FLAG_OVERLAPPED));break;
      case 4:{HANDLE duplicate=NULL;if(!DuplicateHandle(GetCurrentProcess(),base,
        GetCurrentProcess(),&duplicate,FILE_READ_ATTRIBUTES,FALSE,0))ExitProcess(22);
        r.handle=keep(&r,duplicate);break;}
      case 15:r.handle=keep(&r,opened(GENERIC_READ|GENERIC_WRITE,FILE_FLAG_NO_BUFFERING));break;
      case 16:r.handle=keep(&r,opened(FILE_READ_ATTRIBUTES,FILE_FLAG_OVERLAPPED));break;
      case 17:r.handle=keep(&r,opened(GENERIC_READ|GENERIC_WRITE,FILE_FLAG_WRITE_THROUGH));break;
      case 18:r.handle=keep(&r,opened(GENERIC_READ|GENERIC_WRITE,FILE_FLAG_SEQUENTIAL_SCAN));break;
      case 19:r.handle=keep(&r,opened(GENERIC_READ|GENERIC_WRITE|DELETE,FILE_FLAG_DELETE_ON_CLOSE));break;
    }
    r.independent=keep(&r,opened(GENERIC_READ|GENERIC_WRITE,0));
  }else switch(role) {
    case 5:
      r.directory=TRUE;if(!CreateDirectoryW(L"state-dir-v1",NULL))ExitProcess(23);
      r.handle=keep(&r,CreateFileW(L"state-dir-v1",GENERIC_READ,7,NULL,
        OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS,NULL));break;
    case 6:r.handle=keep(&r,CreateFileW(L"NUL",GENERIC_READ|GENERIC_WRITE,7,NULL,OPEN_EXISTING,0,NULL));break;
    case 7:r.handle=keep(&r,CreateFileW(L"CONIN$",GENERIC_READ|GENERIC_WRITE,3,NULL,OPEN_EXISTING,0,NULL));break;
    case 8:r.handle=keep(&r,CreateFileW(L"CONOUT$",GENERIC_READ|GENERIC_WRITE,3,NULL,OPEN_EXISTING,0,NULL));break;
    case 9:case 10:{HANDLE read_pipe,write_pipe;if(!CreatePipe(&read_pipe,&write_pipe,NULL,4096))ExitProcess(24);
      keep(&r,read_pipe);keep(&r,write_pipe);r.handle=role==9?read_pipe:write_pipe;break;}
    case 11:r.handle=keep(&r,CreateEventW(NULL,TRUE,FALSE,NULL));break;
    case 12:r.handle=(HANDLE)(uintptr_t)0x1234;break;
    case 13:r.handle=GetCurrentProcess();break;
    case 14:r.handle=GetCurrentThread();break;
  }
  return r;
}
static void release(Resource *r) {
  for(unsigned i=0;i<r->count;++i)if(!CloseHandle(r->owned[i]))ExitProcess(25);
  if(r->file&&!DeleteFileW(L"state-v1.bin")&&GetLastError()!=ERROR_FILE_NOT_FOUND)ExitProcess(26);
  if(r->directory&&!RemoveDirectoryW(L"state-dir-v1")&&GetLastError()!=ERROR_PATH_NOT_FOUND&&GetLastError()!=ERROR_FILE_NOT_FOUND)ExitProcess(27);
}
static void snapshot(HANDLE handle) {
  static const unsigned classes[]={14,16,41,43};
  control_char('[');
  for(unsigned i=0;i<4;++i) {
    __declspec(align(16)) unsigned char data[16];IoStatus io;
    memset(data,0xA5,sizeof data);memset(&io,0xA5,sizeof io);
    ULONG length=i==0?8:4;LONG status=query_file(handle,&io,data,length,classes[i]);
    if(status==0x103)ExitProcess(28);
    if(i)control_char(',');control_print("[%lu,",(unsigned long)(ULONG)status);hex(data,length);control_char(']');
  }
  control_char(']');
}
static void observe(Resource *r,unsigned role,unsigned sequence,unsigned step,
    unsigned information_class,uint64_t value,unsigned length) {
  __declspec(align(16)) unsigned char data[64];IoStatus io;
  memset(data,0xA5,sizeof data);memcpy(data,&value,sizeof value);memset(&io,0xA5,sizeof io);
  control_print("{\"role\":\"%s\",\"sequence\":%u,\"step\":%u,\"class\":%u,\"length\":%u,\"value\":",
    roles[role],sequence,step,information_class,length);hex(&value,sizeof value);
  control_text(",\"before\":");snapshot(r->handle);
  LONG result=set_file(r->handle,&io,data,length,information_class);
  if(result==0x103)ExitProcess(29);
  control_print(",\"status\":%lu,\"io\":",(unsigned long)(ULONG)result);hex(&io,sizeof io);
  control_text(",\"input_after\":");hex(data,16);
  control_text(",\"after\":");snapshot(r->handle);
  if(r->parent){control_text(",\"parent_after\":");snapshot(r->parent);}
  if(r->independent){control_text(",\"independent_after\":");snapshot(r->independent);}
  control_text("}\n");
}
void entry(void) {
  control_sink=GetStdHandle(STD_OUTPUT_HANDLE);
  HMODULE module=GetModuleHandleW(L"ntdll.dll");
  query_file=(InformationFn)(uintptr_t)GetProcAddress(module,"NtQueryInformationFile");
  set_file=(InformationFn)(uintptr_t)GetProcAddress(module,"NtSetInformationFile");
  if(!query_file||!set_file)ExitProcess(30);
  BOOL allocated=FALSE;if(GetConsoleWindow()==NULL)allocated=AllocConsole();
  control_print("{\"schema\":\"rax-native-file-state-scalars-v1\",\"pointer_bytes\":%zu,\"set_leaf\":",sizeof(void *));
  hex((const void *)(uintptr_t)set_file,64);control_text("}\n");
  // Exclude lazy Win32/console resource initialization from the setter loop.
  for(unsigned role=0;role<sizeof roles/sizeof roles[0];++role) {
    Resource warm=acquire(role);release(&warm);
  }
  DWORD before,after;if(!GetProcessHandleCount(GetCurrentProcess(),&before))ExitProcess(31);
  const unsigned classes[]={14,16,41,43};const uint64_t *values[]={positions,modes,notifications,priorities};
  const unsigned counts[]={sizeof positions/sizeof positions[0],sizeof modes/sizeof modes[0],
    sizeof notifications/sizeof notifications[0],sizeof priorities/sizeof priorities[0]};
  unsigned rows=0;
  for(unsigned role=0;role<sizeof roles/sizeof roles[0];++role) {
    for(unsigned c=0;c<4;++c)for(unsigned v=0;v<counts[c];++v)
      for(unsigned l=0;l<sizeof lengths/sizeof lengths[0];++l) {
        Resource r=acquire(role);observe(&r,role,0,v,classes[c],values[c][v],lengths[l]);release(&r);++rows;
      }
    for(unsigned c=0;c<4;++c) {
      Resource r=acquire(role);
      for(unsigned v=0;v<counts[c];++v){observe(&r,role,1,v,classes[c],values[c][v],c==0?8:4);++rows;}
      release(&r);
    }
  }
  if(!GetProcessHandleCount(GetCurrentProcess(),&after))ExitProcess(32);
  control_print("{\"handles_before\":%lu,\"handles_after\":%lu,\"rows\":%u}\n",
    (unsigned long)before,(unsigned long)after,rows);
  control_flush();if(allocated)FreeConsole();ExitProcess(0);
}
