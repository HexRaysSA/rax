#include <windows.h>
#include <winternl.h>
#include <cstdio>
#include <cstring>
#include <initializer_list>
using Create = LONG(NTAPI*)(HANDLE*,ACCESS_MASK,OBJECT_ATTRIBUTES*,ULONG,ULONG);
using Query = LONG(NTAPI*)(HANDLE,ULONG,void*,ULONG,ULONG*);
using Wait = LONG(NTAPI*)(HANDLE,BOOLEAN,LARGE_INTEGER*);
using State = LONG(NTAPI*)(HANDLE,LONG*);
using Close = LONG(NTAPI*)(HANDLE);
int main() {
    setvbuf(stdout,nullptr,_IONBF,0);
    auto ntdll=GetModuleHandleW(L"ntdll.dll");
    auto create=reinterpret_cast<Create>(GetProcAddress(ntdll,"NtCreateEvent"));
    auto query=reinterpret_cast<Query>(GetProcAddress(ntdll,"NtQueryEvent"));
    auto query_object=reinterpret_cast<Query>(GetProcAddress(ntdll,"NtQueryObject"));
    auto wait=reinterpret_cast<Wait>(GetProcAddress(ntdll,"NtWaitForSingleObject"));
    auto set=reinterpret_cast<State>(GetProcAddress(ntdll,"NtSetEvent"));
    auto reset=reinterpret_cast<State>(GetProcAddress(ntdll,"NtResetEvent"));
    auto close=reinterpret_cast<Close>(GetProcAddress(ntdll,"NtClose"));
    auto pages=static_cast<unsigned char*>(VirtualAlloc(nullptr,16384,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE));
    if(!create||!query||!query_object||!wait||!set||!reset||!close||!pages)return 1;
    DWORD old; LARGE_INTEGER zero{};
    for(ULONG access:{0u,1u,2u,3u,4u,0x100000u,0xF0000u,0x1F0003u,0x02000000u,0x80000000u,0x40000000u,0x20000000u,0x10000000u,0x01000000u,0x001F0007u,0xFFFFFFFFu}) {
        HANDLE h=reinterpret_cast<HANDLE>(ULONG_PTR(0xA5A5A5A5));auto s=create(&h,access,nullptr,0,0);
        unsigned char info[128]{};auto qs=s>=0?query_object(h,0,info,sizeof(PUBLIC_OBJECT_BASIC_INFORMATION),nullptr):s;
        LONG prev=0xA5A5A5A5;auto ss=s>=0?set(h,&prev):s;auto ws=s>=0?wait(h,FALSE,&zero):s;
        DWORD flags=0;if(s>=0)GetHandleInformation(h,&flags);
        printf("pointer=%zu access=%08lX status=%08lX handle=%p query=%08lX grant=%08lX set=%08lX previous=%08lX wait=%08lX flags=%lu\n",sizeof(void*),access,s,h,qs,*reinterpret_cast<ULONG*>(info+4),ss,prev,ws,flags);
        if(s>=0)close(h);
    }
    for(ULONG type:{0u,1u,2u,0xFFFFFFFFu})for(ULONG initial:{0u,1u,2u,255u,256u,257u}) {
        HANDLE h=reinterpret_cast<HANDLE>(ULONG_PTR(0xA5A5A5A5));auto s=create(&h,0x1F0003,nullptr,type,initial);
        LONG info[2]={-1,-1};auto qs=s>=0?query(h,0,info,sizeof(info),nullptr):s;
        auto w1=s>=0?wait(h,FALSE,&zero):s;auto w2=s>=0?wait(h,FALSE,&zero):s;
        printf("pointer=%zu type=%08lX initial=%08lX status=%08lX handle=%p query=%08lX event_type=%ld event_state=%ld wait1=%08lX wait2=%08lX\n",sizeof(void*),type,initial,s,h,qs,info[0],info[1],w1,w2);if(s>=0)close(h);
    }
    for(unsigned role=0;role<26;++role) {
        VirtualProtect(pages,16384,PAGE_READWRITE,&old);memset(pages,0xA5,16384);
        auto out=reinterpret_cast<HANDLE*>(pages);OBJECT_ATTRIBUTES attrs{};attrs.Length=sizeof(attrs);
        auto oa=static_cast<OBJECT_ATTRIBUTES*>(nullptr);ULONG type=0,access=0x1F0003;
        switch(role) {
        case 0:out=nullptr;break;
        case 1:out=reinterpret_cast<HANDLE*>(pages+1);break;
        case 2:out=reinterpret_cast<HANDLE*>(pages+4);break;
        case 3:out=nullptr;type=99;break;
        case 4:VirtualProtect(pages,4096,PAGE_READONLY,&old);type=99;break;
        case 5:VirtualProtect(pages,4096,PAGE_READWRITE|PAGE_GUARD,&old);type=99;break;
        case 6:VirtualProtect(pages,4096,PAGE_READWRITE|PAGE_GUARD,&old);break;
        case 7:oa=reinterpret_cast<OBJECT_ATTRIBUTES*>(1);break;
        case 8:oa=reinterpret_cast<OBJECT_ATTRIBUTES*>(1);type=99;break;
        case 9:out=nullptr;oa=reinterpret_cast<OBJECT_ATTRIBUTES*>(1);break;
        case 10:oa=&attrs;break;
        case 11:oa=&attrs;attrs.Length=0;break;
        case 12:oa=&attrs;attrs.Attributes=2;break;
        case 13:oa=&attrs;attrs.Attributes=0x80000000;break;
        case 14:oa=&attrs;attrs.RootDirectory=reinterpret_cast<HANDLE>(ULONG_PTR(0x1234));break;
        case 15:oa=&attrs;attrs.SecurityDescriptor=reinterpret_cast<void*>(1);break;
        case 16:oa=&attrs;attrs.SecurityQualityOfService=reinterpret_cast<void*>(1);break;
        case 17:oa=reinterpret_cast<OBJECT_ATTRIBUTES*>(pages+4096);memcpy(oa,&attrs,sizeof(attrs));VirtualProtect(pages+4096,4096,PAGE_READWRITE|PAGE_GUARD,&old);break;
        case 18:oa=&attrs;attrs.Length=sizeof(attrs)+4;break;
        case 19:out=reinterpret_cast<HANDLE*>(pages+4092);VirtualProtect(pages+4096,4096,PAGE_NOACCESS,&old);break;
        case 20:out=reinterpret_cast<HANDLE*>(pages+1);type=99;break;
        case 21:VirtualProtect(pages,4096,PAGE_READONLY,&old);access=4;break;
        case 22:oa=&attrs;attrs.Attributes=0x80;break;
        case 23:oa=&attrs;attrs.Attributes=0x200;break;
        case 24:oa=&attrs;attrs.Attributes=0x100;break;
        case 25:oa=&attrs;attrs.Attributes=0x40;break;
        }
        auto s=create(out,access,oa,type,0);MEMORY_BASIC_INFORMATION a{},b{};VirtualQuery(pages,&a,sizeof(a));VirtualQuery(pages+4096,&b,sizeof(b));
        VirtualProtect(pages,16384,PAGE_READWRITE,&old);HANDLE h=nullptr;if(out&&reinterpret_cast<unsigned char*>(out)>=pages&&reinterpret_cast<unsigned char*>(out)<pages+8192)memcpy(&h,out,sizeof(h));
        DWORD flags=0;if(s>=0){GetHandleInformation(h,&flags);close(h);}
        printf("pointer=%zu create_role=%u status=%08lX output_protect=%08lX attrs_protect=%08lX handle=%p flags=%lu prefix=",sizeof(void*),role,s,a.Protect,b.Protect,h,flags);for(unsigned i=0;i<16;++i)printf("%02X",pages[i]);printf("\n");
    }
    for(unsigned role=0;role<11;++role)for(unsigned op=0;op<2;++op) {
        VirtualProtect(pages,16384,PAGE_READWRITE,&old);memset(pages,0xA5,16384);HANDLE h;auto cs=create(&h,0x1F0003,nullptr,0,op);
        auto prev=reinterpret_cast<LONG*>(pages);HANDLE target=h;
        switch(role){case 0:prev=nullptr;break;case 1:prev=reinterpret_cast<LONG*>(pages+1);break;case 2:prev=reinterpret_cast<LONG*>(1);break;case 3:VirtualProtect(pages,4096,PAGE_READONLY,&old);break;case 4:VirtualProtect(pages,4096,PAGE_READWRITE|PAGE_GUARD,&old);break;case 5:target=nullptr;break;case 6:target=GetCurrentProcess();break;case 7:target=nullptr;prev=reinterpret_cast<LONG*>(1);break;case 8:target=GetCurrentProcess();prev=reinterpret_cast<LONG*>(1);break;case 9:{auto mutex=CreateMutexW(nullptr,FALSE,nullptr);DuplicateHandle(GetCurrentProcess(),mutex,GetCurrentProcess(),&target,0,FALSE,0);CloseHandle(mutex);break;}case 10:{auto event=CreateEventW(nullptr,TRUE,FALSE,nullptr);DuplicateHandle(GetCurrentProcess(),event,GetCurrentProcess(),&target,0,FALSE,0);CloseHandle(event);VirtualProtect(pages,4096,PAGE_READWRITE|PAGE_GUARD,&old);break;}}
        auto s=(op?reset:set)(target,prev);LONG info[2]={-1,-1};auto qs=query(h,0,info,sizeof(info),nullptr);MEMORY_BASIC_INFORMATION a{};VirtualQuery(pages,&a,sizeof(a));VirtualProtect(pages,16384,PAGE_READWRITE,&old);
        printf("pointer=%zu state_role=%u op=%s create=%08lX status=%08lX protect=%08lX previous=%08lX query=%08lX state=%ld\n",sizeof(void*),role,op?"reset":"set",cs,s,a.Protect,*reinterpret_cast<ULONG*>(pages),qs,info[1]);close(h);if(role==9||role==10)close(target);
    }

    for(ULONG flags:{1u,2u,4u,8u,0x10u,0x20u,0x40u,0x80u,0x100u,0x200u,0x400u,0x800u,0x1000u,0x2000u}) {
        OBJECT_ATTRIBUTES oa{};oa.Length=sizeof(oa);oa.Attributes=flags;HANDLE h=reinterpret_cast<HANDLE>(ULONG_PTR(0xA5A5A5A5));
        auto s=create(&h,0x1F0003,&oa,0,0);DWORD hf=0;if(s>=0){GetHandleInformation(h,&hf);close(h);}
        printf("pointer=%zu attributes=%08lX status=%08lX handle=%p handle_flags=%lu\n",sizeof(void*),flags,s,h,hf);
    }
    for(ULONG value:{2u,255u}) {
        HANDLE h;create(&h,0x1F0003,nullptr,0,value);LONG previous=-1;auto ss=set(h,&previous);
        printf("pointer=%zu raw_initial=%lu op=set status=%08lX previous=%ld\n",sizeof(void*),value,ss,previous);close(h);
        create(&h,0x1F0003,nullptr,0,value);previous=-1;auto rs=reset(h,&previous);
        printf("pointer=%zu raw_initial=%lu op=reset status=%08lX previous=%ld\n",sizeof(void*),value,rs,previous);close(h);
    }
    for(unsigned role=0;role<28;++role) {
        VirtualProtect(pages,16384,PAGE_READWRITE,&old);memset(pages,0xA5,16384);OBJECT_ATTRIBUTES oa{};oa.Length=sizeof(oa);
        auto attrs=reinterpret_cast<OBJECT_ATTRIBUTES*>(pages+4096);memcpy(attrs,&oa,sizeof(oa));HANDLE *output=reinterpret_cast<HANDLE*>(pages);ULONG type=0;
        switch(role){
        case 0:attrs=reinterpret_cast<OBJECT_ATTRIBUTES*>(pages+4097);memcpy(attrs,&oa,sizeof(oa));break;
        case 1:attrs=reinterpret_cast<OBJECT_ATTRIBUTES*>(pages+4100);memcpy(attrs,&oa,sizeof(oa));break;
        case 2:VirtualProtect(pages+4096,4096,PAGE_READONLY,&old);break;
        case 3:VirtualProtect(pages+4096,4096,PAGE_NOACCESS,&old);break;
        case 4:VirtualProtect(pages+4096,4096,PAGE_READWRITE|PAGE_GUARD,&old);type=99;break;
        case 5:attrs->Attributes=0x80000000;type=99;break;
        case 6:attrs->Length=0;type=99;break;
        case 7:attrs->ObjectName=reinterpret_cast<UNICODE_STRING*>(1);type=99;break;
        case 8:attrs->SecurityDescriptor=pages+8193;break;
        case 9:attrs->SecurityQualityOfService=pages+8193;break;
        case 10:attrs->SecurityQualityOfService=pages+8192;memset(pages+8192,0,16);break;
        case 11:attrs->SecurityQualityOfService=pages+8192;memset(pages+8192,0,16);*reinterpret_cast<ULONG*>(pages+8192)=12;break;
        case 12:attrs->ObjectName=reinterpret_cast<UNICODE_STRING*>(pages+8192);memset(pages+8192,0,16);break;
        case 13:attrs->RootDirectory=reinterpret_cast<HANDLE>(ULONG_PTR(0x1234));type=99;break;
        case 14:attrs=reinterpret_cast<OBJECT_ATTRIBUTES*>(pages+8192-sizeof(oa));memcpy(attrs,&oa,sizeof(oa));VirtualProtect(pages+8192,4096,PAGE_NOACCESS,&old);break;
        case 15:attrs=reinterpret_cast<OBJECT_ATTRIBUTES*>(pages+8192-sizeof(oa)+sizeof(void*));memcpy(attrs,&oa,sizeof(oa));VirtualProtect(pages+8192,4096,PAGE_NOACCESS,&old);break;
        case 16:attrs->SecurityDescriptor=pages+8192;memset(pages+8192,0,64);break;
        case 17:attrs->SecurityDescriptor=pages+8192;memset(pages+8192,0,64);pages[8192]=1;break;
        case 18:output=reinterpret_cast<HANDLE*>(pages+4096-sizeof(void*)+1);VirtualProtect(pages+4096,4096,PAGE_NOACCESS,&old);attrs=nullptr;break;
        case 19:attrs->ObjectName=reinterpret_cast<UNICODE_STRING*>(pages+8192);memset(pages+8192,0,16);attrs->RootDirectory=reinterpret_cast<HANDLE>(ULONG_PTR(0x1234));break;
        case 20:attrs->Attributes=0x80000000;VirtualProtect(pages+4096,4096,PAGE_READWRITE|PAGE_GUARD,&old);break;
        case 21:attrs->Attributes=0x80000000;VirtualProtect(pages,4096,PAGE_READWRITE|PAGE_GUARD,&old);break;
        case 22:attrs->SecurityDescriptor=reinterpret_cast<void*>(1);type=99;break;
        case 23:attrs->SecurityQualityOfService=reinterpret_cast<void*>(1);type=99;break;
        case 24:attrs->Length=0;VirtualProtect(pages,4096,PAGE_READWRITE|PAGE_GUARD,&old);break;
        case 25:attrs->Attributes=2;output=reinterpret_cast<HANDLE*>(pages+4096);break;
        case 26:attrs=nullptr;output=reinterpret_cast<HANDLE*>(pages+4096);VirtualProtect(pages+4096,4096,PAGE_READONLY,&old);break;
        case 27:attrs->ObjectName=reinterpret_cast<UNICODE_STRING*>(1);break;
        }
        auto s=create(output,0x1F0003,attrs,type,0);MEMORY_BASIC_INFORMATION a{},b{};VirtualQuery(pages,&a,sizeof(a));VirtualQuery(pages+4096,&b,sizeof(b));VirtualProtect(pages,16384,PAGE_READWRITE,&old);HANDLE h;memcpy(&h,output,sizeof(h));if(s>=0)close(h);
        printf("pointer=%zu attrs_role=%u status=%08lX output_protect=%08lX attrs_protect=%08lX handle=%p\n",sizeof(void*),role,s,a.Protect,b.Protect,h);
    }
    VirtualFree(pages,0,MEM_RELEASE);
}
