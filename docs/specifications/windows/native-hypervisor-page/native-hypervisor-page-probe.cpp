#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <algorithm>
#include <initializer_list>

using Query = LONG (NTAPI *)(ULONG, PVOID, ULONG, PULONG);
static Query query;
static ULONG page, ordinal;
struct Region {
    unsigned char *p;
    Region() : p(static_cast<unsigned char *>(VirtualAlloc(nullptr, 8 * page,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE))) {
        if (!p) ExitProcess(2);
        std::memset(p, 0xA5, 8 * page);
    }
    ~Region() { if (!VirtualFree(p, 0, MEM_RELEASE)) ExitProcess(3); }
    void protect(unsigned offset, DWORD mode) {
        DWORD previous;
        if (!VirtualProtect(p + offset, page, mode, &previous)) ExitProcess(4);
    }
};
static LONG invoke(void *output, ULONG bytes, ULONG *returned, ULONG *exception) {
    LONG status = static_cast<LONG>(0xDEADBEEF);
    *exception = 0;
    __try { status = query(197, output, bytes, returned); }
    __except (EXCEPTION_EXECUTE_HANDLER) { *exception = GetExceptionCode(); }
    return status;
}
static SIZE_T read(const void *p, unsigned char *out, SIZE_T bytes) {
    MEMORY_BASIC_INFORMATION i;
    if (!p || !VirtualQuery(p, &i, sizeof i) || i.State != MEM_COMMIT ||
        (i.Protect & (PAGE_NOACCESS | PAGE_GUARD))) return 0;
    SIZE_T available = static_cast<const unsigned char *>(i.BaseAddress) + i.RegionSize - static_cast<const unsigned char *>(p);
    SIZE_T got = 0;
    ReadProcessMemory(GetCurrentProcess(),p,out,std::min(bytes,available),&got);
    return got;
}
static void capture(const char *name, const void *p) {
    unsigned char data[32]; SIZE_T got = read(p,data,sizeof data);
    std::printf(" %s-captured=%zu %s=",name,got,name);
    for(SIZE_T j=0;j<got;++j)std::printf("%02X",data[j]);
}
static void run(const char *label, ULONG bytes, unsigned mode=0, unsigned offset=0) {
    Region output,result;
    unsigned char *op=output.p+128;
    auto *rp=reinterpret_cast<ULONG *>(result.p+128);
    switch(mode) {
    case 1:op=nullptr;break;
    case 2:op=reinterpret_cast<unsigned char *>(1);break;
    case 3:rp=nullptr;break;
    case 4:rp=reinterpret_cast<ULONG *>(1);break;
    case 5:output.protect(0,PAGE_READONLY);break;
    case 6:output.protect(0,PAGE_READWRITE|PAGE_GUARD);break;
    case 7:result.protect(0,PAGE_READONLY);break;
    case 8:result.protect(0,PAGE_READWRITE|PAGE_GUARD);break;
    case 9:output.protect(page,PAGE_NOACCESS);op=output.p+page-offset;break;
    case 10:output.protect(page,PAGE_READONLY);op=output.p+page-offset;break;
    case 11:result.protect(page,PAGE_NOACCESS);rp=reinterpret_cast<ULONG *>(result.p+page-offset);break;
    case 12:rp=reinterpret_cast<ULONG *>(op+offset);break;
    case 13:op+=offset;break;
    case 14:rp=reinterpret_cast<ULONG *>(result.p+128+offset);break;
    case 15:op=nullptr;rp=reinterpret_cast<ULONG *>(1);break;
    case 16:output.protect(0,PAGE_NOACCESS);break;
    case 17:op=nullptr;result.protect(0,PAGE_READWRITE|PAGE_GUARD);break;
    case 18:output.protect(0,PAGE_READWRITE|PAGE_GUARD);result.protect(0,PAGE_READONLY);break;
    case 19:output.protect(0,PAGE_READONLY);result.protect(0,PAGE_READWRITE|PAGE_GUARD);break;
    case 20:op=reinterpret_cast<unsigned char *>(static_cast<uintptr_t>(-4));break;
    }
    for(unsigned repeat=0;repeat<(mode==6||mode==8||mode==17||mode==18||mode==19?2u:1u);++repeat){
        ULONG exception;
        auto status=invoke(op,bytes,rp,&exception);
        MEMORY_BASIC_INFORMATION oi,ri;
        VirtualQuery(output.p,&oi,sizeof oi);VirtualQuery(result.p,&ri,sizeof ri);
        std::printf("case=%u label=%s width=%zu bytes=%lu mode=%u offset=%u repeat=%u status=%08lX exception=%08lX output-guard=%lu returned-guard=%lu",ordinal++,label,sizeof(void *),bytes,mode,offset,repeat,static_cast<ULONG>(status),exception,oi.Protect&PAGE_GUARD,ri.Protect&PAGE_GUARD);
        capture("output",op);capture("returned",rp);capture("backing",result.p+128);std::puts("");
    }
}
static void ranges() {
    if constexpr(sizeof(void *)==8) {
        constexpr uintptr_t limit=0x7FFFFFFF0000ull;
        auto *span=static_cast<unsigned char *>(VirtualAlloc(reinterpret_cast<void *>(limit-65536),65536,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE));
        if(!span)ExitProcess(6);
        for(unsigned role=0;role<2;++role){
            Region output,result;
            DWORD previous;VirtualProtect(span+65536-page,page,PAGE_READWRITE|PAGE_GUARD,&previous);
            void *op=role==0?span+65532:output.p;
            auto *rp=reinterpret_cast<ULONG *>(role==1?span+65534:result.p);
            ULONG exception;auto status=invoke(op,8,rp,&exception);
            MEMORY_BASIC_INFORMATION i;VirtualQuery(span+65536-page,&i,sizeof i);
            std::printf("range-guard role=%u width=%zu status=%08lX exception=%08lX guard=%lu\n",role,sizeof(void *),static_cast<ULONG>(status),exception,i.Protect&PAGE_GUARD);
            VirtualProtect(span+65536-page,page,PAGE_READWRITE,&previous);
        }
        VirtualFree(span,0,MEM_RELEASE);
    }
}
int main(){
    SYSTEM_INFO i;GetSystemInfo(&i);page=i.dwPageSize;
    query=reinterpret_cast<Query>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtQuerySystemInformation"));
    if(!query)return 5;
    std::printf("profile width=%zu page=%lu class=197\n",sizeof(void *),page);
    for(ULONG bytes:{0ul,1ul,2ul,3ul,4ul,5ul,7ul,8ul,9ul,12ul,16ul,32ul})run("length",bytes);
    for(ULONG bytes:{0ul,3ul,4ul,7ul,8ul,9ul,16ul})for(unsigned mode=1;mode<=19;++mode){if(mode>=9&&mode<=14)continue;run("fault",bytes,mode);}
    for(unsigned offset=1;offset<=10;++offset){for(unsigned mode:{9u,10u,11u,12u,13u,14u})run("boundary-alias-alignment",8,mode,offset);}
    for(unsigned offset:{4u,8u,16u,32u})run("unused-output-span",32,9,offset);
    run("huge-length",0xFFFFFFFFul);
    run("output-start-alias",8,12,0);
    for(ULONG bytes:{0ul,1ul,3ul,4ul,8ul,32ul})run("upper-output",bytes,20);
    if constexpr(sizeof(void *)==4) {
        for(ULONG bytes:{4095ul,4096ul,4097ul,65535ul,65536ul,65537ul,1048575ul,1048576ul,1048577ul,0x01000000ul,0x7FFFFFE0ul,0x7FFFFFECul,0x7FFFFFF0ul,0x7FFFFFFCul,0x80000000ul,0xFFFFFFF0ul,0xFFFFFFF8ul,0xFFFFFFFCul,0xFFFFFFFDul,0xFFFFFFFEul})run("wow64-capture-size",bytes);
        for(unsigned mode:{1u,2u,4u,6u,8u,17u})run("wow64-huge-fault",0xFFFFFFFFul,mode);
    }
    ranges();std::printf("complete cases=%u\n",ordinal);return 0;
}
