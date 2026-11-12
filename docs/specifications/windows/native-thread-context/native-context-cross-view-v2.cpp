#include <windows.h>
using NativeContext = LONG(NTAPI *)(HANDLE, void *);
using Initialize = BOOL(WINAPI *)(void *, DWORD, void **, DWORD *);
using Features = BOOL(WINAPI *)(void *, unsigned long long *);
using Mask = BOOL(WINAPI *)(void *, unsigned long long);
using Locate = void *(WINAPI *)(void *, DWORD, DWORD *);
using Context = BOOL(WINAPI *)(HANDLE, void *);
#pragma pack(push, 1)
struct Packet { DWORD operation, tid, status, error; unsigned long long mask; unsigned char ymm[256]; unsigned long long debug[6]; };
#pragma pack(pop)
static_assert(sizeof(Packet) == 328);
static bool write_all(HANDLE h, const void *p, DWORD size) {
    const auto *s=static_cast<const unsigned char*>(p);
    while(size){DWORD n=0;if(!WriteFile(h,s,size,&n,nullptr)||!n)return false;s+=n;size-=n;}return true;
}
static bool read_all(HANDLE h, void *p, DWORD size) {
    auto *s=static_cast<unsigned char*>(p);
    while(size){DWORD n=0;if(!ReadFile(h,s,size,&n,nullptr)||!n)return false;s+=n;size-=n;}return true;
}
static void row(DWORD kind, const void *p, DWORD size) {
    const char hex[]="0123456789abcdef"; const auto *b=static_cast<const unsigned char*>(p);char line[4096];unsigned n=0;
    for(int shift=28;shift>=0;shift-=4)line[n++]=hex[(kind>>shift)&15];line[n++]=' ';
    for(DWORD i=0;i<size;++i){line[n++]=hex[b[i]>>4];line[n++]=hex[b[i]&15];}line[n++]='\n';
    if(!write_all(GetStdHandle(STD_OUTPUT_HANDLE),line,n))ExitProcess(99);
}
#if defined(_M_ARM64)
extern "C" __declspec(noreturn) void entry() {
    const wchar_t *arg=GetCommandLineW();
    if(*arg==L'"'){++arg;while(*arg&&*arg!=L'"')++arg;if(*arg)++arg;}else while(*arg&&*arg!=L' ')++arg;
    while(*arg==L' ')++arg;
    wchar_t command64[]=L"query-x64.exe",command86[]=L"query-x86.exe";
    wchar_t *command=arg[1]==L'8'?command86:command64;
    SECURITY_ATTRIBUTES sa={sizeof(sa),nullptr,TRUE};HANDLE input_read=nullptr,input_write=nullptr,output_read=nullptr,output_write=nullptr;
    if(!CreatePipe(&input_read,&input_write,&sa,0)||!CreatePipe(&output_read,&output_write,&sa,0))ExitProcess(10);
    if(!SetHandleInformation(input_write,HANDLE_FLAG_INHERIT,0)||!SetHandleInformation(output_read,HANDLE_FLAG_INHERIT,0))ExitProcess(11);
    auto null_error=CreateFileW(L"NUL",GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,&sa,OPEN_EXISTING,0,nullptr);
    STARTUPINFOW startup={};startup.cb=sizeof(startup);startup.dwFlags=STARTF_USESTDHANDLES;startup.hStdInput=input_read;startup.hStdOutput=output_write;startup.hStdError=null_error;
    PROCESS_INFORMATION child={};if(!CreateProcessW(nullptr,command,nullptr,nullptr,TRUE,0,nullptr,nullptr,&startup,&child))ExitProcess(12);
    CloseHandle(input_read);CloseHandle(output_write);CloseHandle(null_error);CloseHandle(child.hThread);
    Packet packet={};DWORD failure=0;HANDLE thread=nullptr;bool captured=false;CONTEXT original={};
    auto get=reinterpret_cast<NativeContext>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtGetContextThread"));
    auto set=reinterpret_cast<NativeContext>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtSetContextThread"));
    if(!get||!set||!read_all(output_read,&packet,sizeof(packet))||packet.operation!=0||packet.status){failure=13;}
    if(!failure){row(0,&packet,sizeof(packet));thread=OpenThread(THREAD_GET_CONTEXT|THREAD_SET_CONTEXT|THREAD_QUERY_INFORMATION,FALSE,packet.tid);if(!thread)failure=14;}
    if(!failure){original.ContextFlags=0x0040001f;LONG status=get(thread,&original);DWORD info[]={DWORD(status),original.ContextFlags};row(1,info,sizeof(info));if(status||((original.ContextFlags&0xff0000)!=0x400000))failure=15;else {captured=true;row(2,&original,sizeof(original));}}
    const char operations[] = {'g','d','s'};
    for(char operation : operations){
        if(failure)break;
        if(!write_all(input_write,&operation,1)||!read_all(output_read,&packet,sizeof(packet))||packet.operation!=DWORD(operation)||packet.status){failure=16;break;}
        row(DWORD(operation),&packet,sizeof(packet));CONTEXT current={};current.ContextFlags=0x0040001f;LONG status=get(thread,&current);DWORD info[]={DWORD(status),current.ContextFlags};row(0x100+DWORD(operation),info,sizeof(info));if(status){failure=17;break;}row(0x200+DWORD(operation),&current,sizeof(current));
        if(operation=='g'||operation=='d'){
            CONTEXT assigned=current;
            if(operation=='g'){
                assigned.ContextFlags=0x00400080;
                auto *vectors=reinterpret_cast<unsigned char*>(&assigned.V[16]);for(DWORD n=0;n<256;++n)vectors[n]=0x5a;
            }else{
                assigned.ContextFlags=0x00400008;assigned.Bcr[0]=0x1e5;assigned.Bvr[0]=0x23456000;assigned.Bvr[4]=0xabcd;
            }
            LONG status=set(thread,&assigned);row(0x300+DWORD(operation),&status,sizeof(status));
            if(status){failure=25;break;}
            char query='g';if(!write_all(input_write,&query,1)||!read_all(output_read,&packet,sizeof(packet))||packet.operation!='g'||packet.status){failure=26;break;}
            row(0x400+DWORD(operation),&packet,sizeof(packet));
            CONTEXT after={};after.ContextFlags=0x0040001f;status=get(thread,&after);row(0x500+DWORD(operation),&after,sizeof(after));if(status){failure=27;break;}
        }

    }
    // Restore the exact native frame captured from this owned child thread.
    if(captured){LONG status=set(thread,&original);row(3,&status,sizeof(status));if(status&&!failure)failure=18;}
    char quit='q';if(!write_all(input_write,&quit,1)||!read_all(output_read,&packet,sizeof(packet))||packet.operation!='q'||packet.status){if(!failure)failure=19;}else row(4,&packet,sizeof(packet));
    if(captured){LONG status=set(thread,&original);row(5,&status,sizeof(status));if(status&&!failure)failure=20;}
    char resume='r';if(!write_all(input_write,&resume,1)&&!failure)failure=21;
    CloseHandle(input_write);CloseHandle(output_read);if(thread)CloseHandle(thread);
    if(WaitForSingleObject(child.hProcess,INFINITE)!=WAIT_OBJECT_0&&!failure)failure=22;
    DWORD exit=0;if(!GetExitCodeProcess(child.hProcess,&exit)&&!failure)failure=23;row(6,&exit,sizeof(exit));CloseHandle(child.hProcess);
    if(exit&&!failure)failure=24;ExitProcess(failure);
}
#else
static DWORD WINAPI worker(void *) {return 0x52415843;}
extern "C" __declspec(noreturn) void entry() {
    auto module=GetModuleHandleW(L"kernel32.dll");
    auto initialize=reinterpret_cast<Initialize>(GetProcAddress(module,"InitializeContext"));
    auto features=reinterpret_cast<Features>(GetProcAddress(module,"GetXStateFeaturesMask"));
    auto mask=reinterpret_cast<Mask>(GetProcAddress(module,"SetXStateFeaturesMask"));
    auto locate=reinterpret_cast<Locate>(GetProcAddress(module,"LocateXStateFeature"));
    auto get=reinterpret_cast<Context>(GetProcAddress(module,"GetThreadContext"));
    auto set=reinterpret_cast<Context>(GetProcAddress(module,"SetThreadContext"));
    if(!initialize||!features||!mask||!locate||!get||!set)ExitProcess(30);
    const DWORD flags=CONTEXT_ALL|CONTEXT_XSTATE;DWORD size=0;initialize(nullptr,flags,nullptr,&size);if(!size||size>16384)ExitProcess(31);
    auto *area=static_cast<unsigned char*>(VirtualAlloc(nullptr,32768,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE));if(!area)ExitProcess(32);
    void *saved=nullptr,*changed=nullptr;DWORD available=16384;if(!initialize(area,flags,&saved,&available))ExitProcess(33);available=16384;if(!initialize(area+16384,flags,&changed,&available))ExitProcess(34);
    DWORD tid=0;auto thread=CreateThread(nullptr,0,worker,nullptr,CREATE_SUSPENDED,&tid);if(!thread)ExitProcess(35);
    if(!mask(saved,4)||!get(thread,saved))ExitProcess(36);unsigned long long before=0;if(!features(saved,&before))ExitProcess(37);
    const auto input=GetStdHandle(STD_INPUT_HANDLE),output=GetStdHandle(STD_OUTPUT_HANDLE);Packet packet={};packet.tid=tid;if(!write_all(output,&packet,sizeof(packet)))ExitProcess(38);
    bool modified=false;char operation=0;
    while(read_all(input,&operation,1)&&operation!='q'){
        packet={};packet.operation=DWORD(operation);packet.tid=tid;static_cast<CONTEXT*>(changed)->ContextFlags=flags;
        if(!mask(changed,4)||!get(thread,changed)){packet.status=1;packet.error=GetLastError();}
        DWORD length=0;auto *state=static_cast<unsigned char*>(locate(changed,2,&length));
        if(!state||length<256){packet.status=2;packet.error=GetLastError();}
        if(!packet.status&&operation=='d'){
            auto *c=static_cast<CONTEXT*>(changed);c->ContextFlags=CONTEXT_DEBUG_REGISTERS;c->Dr0=0x12345000;c->Dr1=0x12345100;c->Dr2=0x12345200;c->Dr3=0x12345300;c->Dr6=0x1234;c->Dr7=0x55;
            if(!set(thread,c)){packet.status=3;packet.error=GetLastError();}
        }
        if(!packet.status&&operation=='s'){
            const DWORD meaningful=sizeof(void*)==4?128:256;for(DWORD n=0;n<meaningful;++n)state[n]=0x3c;
            if(!mask(changed,4)||!set(thread,changed)){packet.status=4;packet.error=GetLastError();}else modified=true;
        }
        static_cast<CONTEXT*>(changed)->ContextFlags=flags;
        if(!packet.status&&(!mask(changed,4)||!get(thread,changed)||!features(changed,&packet.mask))){packet.status=5;packet.error=GetLastError();}
        if(!packet.status){for(DWORD n=0;n<256;++n)packet.ymm[n]=state[n];auto *c=static_cast<CONTEXT*>(changed);packet.debug[0]=c->Dr0;packet.debug[1]=c->Dr1;packet.debug[2]=c->Dr2;packet.debug[3]=c->Dr3;packet.debug[4]=c->Dr6;packet.debug[5]=c->Dr7;}
        if(!write_all(output,&packet,sizeof(packet)))break;
    }
    DWORD length=0;auto *state=static_cast<unsigned char*>(locate(saved,2,&length));const DWORD meaningful=sizeof(void*)==4?128:256;
    if(modified&&!(before&4)&&state)for(DWORD n=0;n<meaningful;++n)state[n]=0;
    static_cast<CONTEXT*>(saved)->ContextFlags=flags;packet={};packet.operation='q';packet.tid=tid;
    if(!mask(saved,modified?4:before)||!set(thread,saved)){packet.status=6;packet.error=GetLastError();}
    write_all(output,&packet,sizeof(packet));if(operation=='q')read_all(input,&operation,1);
    if(ResumeThread(thread)!=1)ExitProcess(39);if(WaitForSingleObject(thread,INFINITE)!=WAIT_OBJECT_0)ExitProcess(40);DWORD code=0;if(!GetExitCodeThread(thread,&code)||code!=0x52415843)ExitProcess(41);
    CloseHandle(thread);VirtualFree(area,0,MEM_RELEASE);ExitProcess(packet.status?42:0);
}
#endif
