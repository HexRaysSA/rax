/* Reuse only standalone native resource/output helpers, never RAX. */
#define entry scalar_control_entry
#include "scalars-v1.c"
#undef entry
#include <excpt.h>

#if defined(_M_IX86)
int __cdecl _except_handler3(void *record,void *frame,void *context,void *dispatch) {
  typedef int (__cdecl *Handler)(void *,void *,void *,void *);static Handler target;
  if(!target)target=(Handler)(uintptr_t)GetProcAddress(LoadLibraryW(L"msvcrt.dll"),"_except_handler3");
  if(!target)ExitProcess(60);return target(record,frame,context,dispatch);
}
#else
EXCEPTION_DISPOSITION __cdecl __C_specific_handler(struct _EXCEPTION_RECORD *record,
    void *frame,struct _CONTEXT *context,struct _DISPATCHER_CONTEXT *dispatch) {
  typedef EXCEPTION_DISPOSITION (__cdecl *Handler)(struct _EXCEPTION_RECORD *,void *,struct _CONTEXT *,struct _DISPATCHER_CONTEXT *);
  static Handler target;if(!target)target=(Handler)(uintptr_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"__C_specific_handler");
  if(!target)ExitProcess(61);return target(record,frame,context,dispatch);
}
#endif

static unsigned char *io_pages,*input_pages;
static void changes(const void *data,size_t size) {
  const unsigned char *p=data;BOOL comma=FALSE;control_char('{');
  for(size_t i=0;i<size;) {
    if(p[i]==0xA5){++i;continue;}if(comma)control_char(',');comma=TRUE;
    control_print("\"%u\":\"",(unsigned)i);
    do{control_print("%02x",(unsigned)p[i++]);}while(i<size&&p[i]!=0xA5);
    control_char('"');
  }
  control_char('}');
}
static DWORD protection(void *address) {
  MEMORY_BASIC_INFORMATION info;if(!VirtualQuery(address,&info,sizeof info))ExitProcess(62);return info.Protect;
}
static void fault_observe(unsigned role,unsigned information_class,unsigned length,unsigned which) {
  Resource r=acquire(role);DWORD prior;
  if(!VirtualProtect(io_pages,8192,PAGE_READWRITE,&prior)||!VirtualProtect(input_pages,8192,PAGE_READWRITE,&prior))ExitProcess(63);
  memset(io_pages,0xA5,8192);memset(input_pages,0xA5,8192);
  IoStatus *io=(IoStatus *)(void *)(io_pages+64);void *input=input_pages+64;
  switch(which) {
    case 1:io=NULL;break;case 2:input=NULL;break;case 3:io=NULL;input=NULL;break;
    case 4:io=(IoStatus *)(uintptr_t)1;break;case 5:input=(void *)(uintptr_t)1;break;
    case 6:io=(IoStatus *)(uintptr_t)1;input=(void *)(uintptr_t)1;break;
    case 7:io=(IoStatus *)(void *)(io_pages+65);break;case 8:input=input_pages+65;break;
    case 9:io=(IoStatus *)(void *)(io_pages+4096-4);break;
    case 10:io=(IoStatus *)(void *)(io_pages+4096-sizeof(void *));break;
    case 11:input=input_pages+4096-4;break;
    case 17:input=io;break;case 18:input=(unsigned char *)io+sizeof(void *);break;
    case 19:input=(void *)(uintptr_t)(~(uintptr_t)0-3);break;
    case 20:io=(IoStatus *)(uintptr_t)(~(uintptr_t)0-3);break;
    case 21:io=(IoStatus *)(void *)(input_pages+68);break;
  }
  uint64_t value=information_class==14?7:information_class==16?0x20:1;
  uintptr_t at=(uintptr_t)input;
  if((at>=(uintptr_t)io_pages&&at<=(uintptr_t)io_pages+8192-8)||
     (at>=(uintptr_t)input_pages&&at<=(uintptr_t)input_pages+8192-8))memcpy(input,&value,8);
  if(!VirtualProtect(io_pages+4096,4096,PAGE_NOACCESS,&prior)||!VirtualProtect(input_pages+4096,4096,PAGE_NOACCESS,&prior))ExitProcess(64);
  switch(which) {
    case 12:if(!VirtualProtect(io_pages,4096,PAGE_READWRITE|PAGE_GUARD,&prior))ExitProcess(65);break;
    case 13:if(!VirtualProtect(input_pages,4096,PAGE_READWRITE|PAGE_GUARD,&prior))ExitProcess(66);break;
    case 14:if(!VirtualProtect(io_pages,4096,PAGE_READWRITE|PAGE_GUARD,&prior)||!VirtualProtect(input_pages,4096,PAGE_READWRITE|PAGE_GUARD,&prior))ExitProcess(67);break;
    case 15:if(!VirtualProtect(input_pages,4096,PAGE_READONLY,&prior))ExitProcess(68);break;
    case 16:if(!VirtualProtect(io_pages,4096,PAGE_READONLY,&prior))ExitProcess(69);break;
  }
  control_print("{\"role\":\"%s\",\"class\":%u,\"length\":%u,\"case\":%u,\"before\":",roles[role],information_class,length,which);snapshot(r.handle);
  LONG returned=(LONG)0xDEADBEEF;DWORD exception=0;
  __try{returned=set_file(r.handle,io,input,length,information_class);}
  __except(EXCEPTION_EXECUTE_HANDLER){exception=GetExceptionCode();}
  if(returned==0x103)ExitProcess(70);
  DWORD io_protect=protection(io_pages),input_protect=protection(input_pages);
  if(!VirtualProtect(io_pages,8192,PAGE_READWRITE,&prior)||!VirtualProtect(input_pages,8192,PAGE_READWRITE,&prior))ExitProcess(71);
  control_print(",\"status\":%lu,\"exception\":%lu,\"io_protect\":%lu,\"input_protect\":%lu,\"io_base\":",
    (unsigned long)(ULONG)returned,(unsigned long)exception,(unsigned long)io_protect,(unsigned long)input_protect);
  changes(io_pages+48,64);control_text(",\"input_base\":");changes(input_pages+48,160);
  control_text(",\"io_tail\":");changes(io_pages+4096-24,48);
  control_text(",\"input_tail\":");changes(input_pages+4096-24,64);
  control_text(",\"after\":");snapshot(r.handle);
  if(r.parent){control_text(",\"parent_after\":");snapshot(r.parent);}
  control_text("}\n");release(&r);
}
void entry(void) {
  control_sink=GetStdHandle(STD_OUTPUT_HANDLE);HMODULE module=GetModuleHandleW(L"ntdll.dll");
  query_file=(InformationFn)(uintptr_t)GetProcAddress(module,"NtQueryInformationFile");
  set_file=(InformationFn)(uintptr_t)GetProcAddress(module,"NtSetInformationFile");if(!query_file||!set_file)ExitProcess(72);
  BOOL allocated=FALSE;if(GetConsoleWindow()==NULL)allocated=AllocConsole();
  for(unsigned role=0;role<sizeof roles/sizeof roles[0];++role){Resource r=acquire(role);release(&r);}
  io_pages=VirtualAlloc(NULL,8192,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
  input_pages=VirtualAlloc(NULL,8192,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);if(!io_pages||!input_pages)ExitProcess(73);
  DWORD before,after;if(!GetProcessHandleCount(GetCurrentProcess(),&before))ExitProcess(74);
  control_print("{\"schema\":\"rax-native-file-state-faults-v1\",\"pointer_bytes\":%zu,\"set_leaf\":",sizeof(void *));hex((const void *)(uintptr_t)set_file,64);control_text("}\n");
  const unsigned selected[]={0,3,4,5,6,7,8,9,10,11,12,15,16};
  const unsigned classes[]={0,14,16,41,43,90,0xFFFFFFFFu};unsigned rows=0;
  for(unsigned ri=0;ri<sizeof selected/sizeof selected[0];++ri)for(unsigned c=0;c<sizeof classes/sizeof classes[0];++c) {
    for(unsigned length=0;length<=12;++length){fault_observe(selected[ri],classes[c],length,0);++rows;}
    for(unsigned which=0;which<=21;++which){fault_observe(selected[ri],classes[c],512,which);++rows;}
  }
  if(!GetProcessHandleCount(GetCurrentProcess(),&after))ExitProcess(75);
  control_print("{\"handles_before\":%lu,\"handles_after\":%lu,\"rows\":%u}\n",(unsigned long)before,(unsigned long)after,rows);
  if(!VirtualFree(io_pages,0,MEM_RELEASE)||!VirtualFree(input_pages,0,MEM_RELEASE))ExitProcess(76);
  control_flush();if(allocated)FreeConsole();ExitProcess(0);
}
