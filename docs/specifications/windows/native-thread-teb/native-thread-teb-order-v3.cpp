#include <windows.h>
#include <initializer_list>

using Query = LONG(NTAPI *)(HANDLE, ULONG, void *, ULONG, ULONG *);
static Query query;
static HANDLE output, thread_handle, handles[18];
static unsigned char *out_pages, *ret_pages, *record_pages;
static char line[4096];
static unsigned position, case_index, creation_flags, life_phase;

static void text(const char *s) {
    while (*s) line[position++] = *s++;
}
static void hex(ULONG_PTR value) {
    const char digits[] = "0123456789abcdef";
    for (unsigned n = sizeof(value) * 2; n; --n)
        line[position++] = digits[(value >> ((n - 1) * 4)) & 15];
}
static void field(ULONG_PTR value) {
    text(" "); hex(value);
}
static void bytes(const unsigned char *p, unsigned size) {
    const char digits[] = "0123456789abcdef";
    text(" ");
    for (unsigned n = 0; n < size; ++n) {
        line[position++] = digits[p[n] >> 4];
        line[position++] = digits[p[n] & 15];
    }
}
static void flush() {
    text("\n");
    DWORD written;
    if (!WriteFile(output, line, position, &written, nullptr) || written != position)
        ExitProcess(3);
    position = 0;
}
static void protect(unsigned char *p, SIZE_T size, DWORD value) {
    DWORD old;
    if (!VirtualProtect(p, size, value, &old)) ExitProcess(4);
}
static DWORD protection(unsigned char *p) {
    MEMORY_BASIC_INFORMATION info;
    if (!VirtualQuery(p, &info, sizeof(info))) ExitProcess(5);
    return info.Protect;
}
// Modes 0..6 use the first page; 7..11 cross into the second page.
static unsigned char *location(unsigned char *p, unsigned mode, unsigned delta) {
    const DWORD protections[] = {PAGE_READONLY, PAGE_NOACCESS,
                                 PAGE_READWRITE | PAGE_GUARD, PAGE_READONLY | PAGE_GUARD};
    if (mode == 1) return nullptr;
    if (mode == 2) return reinterpret_cast<unsigned char *>(ULONG_PTR(1));
    if (mode >= 3 && mode <= 6) protect(p, 4096, protections[mode - 3]);
    if (mode >= 8 && mode <= 11) protect(p + 4096, 4096, protections[mode - 8]);
    return p + 4096 - (mode >= 7 ? 1 : 16) + delta;
}

struct TebInfo { void *buffer; ULONG offset, bytes; };
static unsigned char *target_teb;
static unsigned packet_bytes() { return sizeof(TebInfo); }
static unsigned char *position_for(unsigned char *p,unsigned mode,unsigned delta){if(mode==1)return nullptr;if(mode==2)return reinterpret_cast<unsigned char*>(ULONG_PTR(1));return p+4096-(mode>=7?1:32)+delta;}
static void apply(unsigned char*p,unsigned mode){const DWORD v[]={PAGE_READONLY,PAGE_NOACCESS,PAGE_READWRITE|PAGE_GUARD,PAGE_READONLY|PAGE_GUARD};if(mode>=3&&mode<=6)protect(p,4096,v[mode-3]);if(mode>=8&&mode<=11)protect(p+4096,4096,v[mode-8]);}
static void run(unsigned kind,ULONG offset,ULONG count,ULONG length,unsigned rec_mode=0,unsigned out_mode=0,unsigned ret_mode=0,unsigned rec_delta=0,unsigned out_delta=0,unsigned ret_delta=0){
 unsigned char *pages[]={record_pages,out_pages,ret_pages};for(auto p:pages)protect(p,12288,PAGE_READWRITE);
 for(unsigned n=0;n<12288;++n){record_pages[n]=0xa5;out_pages[n]=0xcc;ret_pages[n]=0xdd;}
 auto record=position_for(record_pages,rec_mode,rec_delta);auto dest=position_for(out_pages,out_mode,out_delta);auto returned=position_for(ret_pages,ret_mode,ret_delta);
 if(out_mode>=20)dest=record_pages+4096-32+(out_mode-20)*4;
 if(ret_mode>=20){const int delta[]={0,4,8,12};returned=(ret_mode<24?record_pages:out_pages)+4096-32+delta[(ret_mode-20)%4];}
 if(rec_mode!=1&&rec_mode!=2){auto info=reinterpret_cast<TebInfo*>(record);info->buffer=dest;info->offset=offset;info->bytes=count;}
 unsigned char before[64],source[64];for(unsigned n=0;n<64;++n){before[n]=record_pages[4096-48+n];source[n]=0xee;}
 SIZE_T read=0;auto teb=kind==7?reinterpret_cast<unsigned char*>(NtCurrentTeb()):target_teb;if(!life_phase||kind==7)ReadProcessMemory(GetCurrentProcess(),teb+offset,source,64,&read);
 apply(record_pages,rec_mode);if(out_mode<20)apply(out_pages,out_mode);if(ret_mode<20)apply(ret_pages,ret_mode);
 LONG status=LONG(0xfeedface);DWORD exception=0;
 __try{status=query(handles[kind],26,record,length,reinterpret_cast<ULONG*>(returned));}__except(EXCEPTION_EXECUTE_HANDLER){exception=GetExceptionCode();}
 DWORD protections[]={protection(record_pages),protection(record_pages+4096),protection(out_pages),protection(out_pages+4096),protection(ret_pages),protection(ret_pages+4096)};
 for(auto p:pages)protect(p,12288,PAGE_READWRITE);
 text("case");field(case_index++);field(kind);field(life_phase);field(offset);field(count);field(length);field(rec_mode);field(out_mode);field(ret_mode);field(rec_delta);field(out_delta);field(ret_delta);field(ULONG(status));field(exception);
 for(DWORD p:protections)field(p);bytes(before,64);bytes(record_pages+4096-48,64);bytes(out_pages+4096-48,96);bytes(ret_pages+4096-48,64);bytes(source,64);flush();
}
using Create=LONG(NTAPI*)(HANDLE*,ULONG,void*,HANDLE,void*,void*,ULONG,SIZE_T,SIZE_T,SIZE_T,void*);
using Terminate=LONG(NTAPI*)(HANDLE,LONG);
struct Basic { LONG status; void *teb; HANDLE pid,tid; ULONG_PTR affinity; LONG priority,base; };
static void matrix(){ULONG off=sizeof(void*)==4?0xf0c:0x1678, count=sizeof(void*),length=packet_bytes();
 for(unsigned rec:{0u,2u,5u,6u,9u})for(unsigned out:{0u,2u,5u,6u,9u})for(unsigned ret:{0u,2u,5u,6u,9u})for(ULONG len:std::initializer_list<ULONG>{0,1,length})run(0,off,count,len,rec,out,ret);
 for(unsigned kind:{0u,1u,7u,8u,9u,16u})for(ULONG offset:std::initializer_list<ULONG>{off,0x1870,0xffffffff})for(ULONG count:std::initializer_list<ULONG>{0,4,8})for(unsigned mode:{0u,2u,5u,6u}){run(kind,offset,count,length,0,mode);run(kind,offset,count,length,0,0,mode);}
}
static HANDLE duplicate(HANDLE h,DWORD access){HANDLE result=nullptr;if(!DuplicateHandle(GetCurrentProcess(),h,GetCurrentProcess(),&result,access,FALSE,0))ExitProcess(6);return result;}
extern "C" __declspec(noreturn) void entry(){output=GetStdHandle(STD_OUTPUT_HANDLE);auto n=GetModuleHandleW(L"ntdll.dll");query=reinterpret_cast<Query>(GetProcAddress(n,"NtQueryInformationThread"));auto create=reinterpret_cast<Create>(GetProcAddress(n,"NtCreateThreadEx"));auto terminate=reinterpret_cast<Terminate>(GetProcAddress(n,"NtTerminateThread"));auto start=reinterpret_cast<void*>(GetProcAddress(n,"RtlExitUserThread"));if(!query||!create||!terminate||!start)ExitProcess(1);
 record_pages=static_cast<unsigned char*>(VirtualAlloc(nullptr,12288,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE));out_pages=static_cast<unsigned char*>(VirtualAlloc(nullptr,12288,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE));ret_pages=static_cast<unsigned char*>(VirtualAlloc(nullptr,12288,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE));if(!record_pages||!out_pages||!ret_pages)ExitProcess(7);
 if(create(&thread_handle,0x1fffff,nullptr,GetCurrentProcess(),start,nullptr,1,0,0,0,nullptr)<0)ExitProcess(8);Basic basic={};ULONG size=0;if(query(thread_handle,0,&basic,sizeof(basic),&size)<0)ExitProcess(9);target_teb=static_cast<unsigned char*>(basic.teb);const unsigned char marker[]={0x32,0x41,0x58,0x21,0x26,0x59,0x41,0x31};SIZE_T written=0;if(!WriteProcessMemory(GetCurrentProcess(),target_teb+(sizeof(void*)==4?0xf0c:0x1678),marker,sizeof(void*),&written))ExitProcess(10);
 handles[0]=thread_handle;const DWORD grants[]={0,8,0x10,0x18,0x40,0x58};for(unsigned i=0;i<6;++i)handles[i+1]=duplicate(thread_handle,grants[i]);handles[7]=GetCurrentThread();handles[8]=GetCurrentProcess();handles[9]=nullptr;handles[10]=reinterpret_cast<HANDLE>(ULONG_PTR(0x12345678));handles[11]=duplicate(thread_handle,0x1fffff);CloseHandle(handles[11]);for(unsigned i=1;i<=3;++i)handles[11+i]=reinterpret_cast<HANDLE>(reinterpret_cast<ULONG_PTR>(thread_handle)|i);handles[15]=duplicate(thread_handle,0x800);
 HANDLE event=CreateEventW(nullptr,FALSE,FALSE,nullptr);if(!event)ExitProcess(11);handles[16]=duplicate(event,0);handles[17]=duplicate(event,1);
 text("width");field(sizeof(void*));field(packet_bytes());flush();life_phase=0;matrix();if(terminate(thread_handle,0x37)<0||WaitForSingleObject(thread_handle,INFINITE)!=WAIT_OBJECT_0)ExitProcess(12);life_phase=1;matrix();for(unsigned i:{0u,1u,2u,3u,4u,5u,6u,15u,16u,17u})if(!CloseHandle(handles[i]))ExitProcess(13);if(!CloseHandle(event))ExitProcess(14);text("count");field(case_index);flush();ExitProcess(0);
}
