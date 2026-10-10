#include <windows.h>
#include <cstdio>
#include <cstring>
#include <vector>
#include <initializer_list>
// Original oracle: only this process's private allocations; always release.
using Allocate = LONG(NTAPI*)(HANDLE, void**, SIZE_T*, ULONG, ULONG, MEM_EXTENDED_PARAMETER*, ULONG);
using Free = LONG(NTAPI*)(HANDLE, void**, SIZE_T*, ULONG);
struct Case { const char* name; int mode; ULONG_PTR low, high, alignment; SIZE_T size; ULONG flags; ULONG protect; ULONG count; };
static LONG guarded_allocate(Allocate allocate, void** base, SIZE_T* size, ULONG flags, ULONG protect, MEM_EXTENDED_PARAMETER* input, ULONG count, DWORD* exception) {
    LONG status=0;
    __try { status=allocate(reinterpret_cast<HANDLE>(LONG_PTR(-1)),base,size,flags,protect,input,count); }
    __except(EXCEPTION_EXECUTE_HANDLER) { *exception=GetExceptionCode(); }
    return status;
}
int main() {
    setvbuf(stdout, nullptr, _IONBF, 0);
    auto dll = GetModuleHandleW(L"ntdll.dll");
    auto allocate = reinterpret_cast<Allocate>(GetProcAddress(dll, "NtAllocateVirtualMemoryEx"));
    auto release = reinterpret_cast<Free>(GetProcAddress(dll, "NtFreeVirtualMemory"));
    if (!allocate || !release) return 1;
    std::vector<Case> cases;
    auto add = [&](const char* name, int mode, ULONG_PTR low=0, ULONG_PTR high=0, ULONG_PTR alignment=0, SIZE_T size=0x1000, ULONG flags=MEM_RESERVE, ULONG protect=PAGE_READWRITE, ULONG count=1) {
        cases.push_back({name, mode, low, high, alignment, size, flags, protect, count});
    };
    add("no-parameters",0); add("zero-requirements",1); add("loader",1,0,0,0,0x02001000,MEM_RESERVE|MEM_TOP_DOWN);
    add("null-parameters",2); add("bad-parameters",3); add("null-requirements",4); add("bad-requirements",5);
    add("unknown-type",6); add("duplicate-address",7); add("numa-zero",8); add("numa-invalid",9); add("attributes-zero",10);
    add("address-and-numa",11); add("reserved-type-bits",12); add("unaligned-parameters",13); add("bad-parameters-zero-count",14); add("unaligned-requirements",15);
    add("align-page",1,0,0,0x1000); add("align-granularity",1,0,0,0x10000); add("align-128k",1,0,0,0x20000);
    add("align-1m",1,0,0,0x100000); add("align-nonpower",1,0,0,0x18000);
    add("low-granularity",1,0x10000); add("low-unaligned",1,0x10001);
    add("high-valid",1,0,0x1fffffff); add("high-unaligned",1,0,0x1fff0000); add("high-max",1,0,~ULONG_PTR(0));
    add("range-bottom",1,0x1000000,0x1ffffff); add("range-top",1,0x1000000,0x1ffffff,0,0x1000,MEM_RESERVE|MEM_TOP_DOWN);
    add("range-aligned",1,0x1000000,0x1ffffff,0x100000); add("range-inverted",1,0x2000000,0x1ffffff);
    add("range-too-small",1,0x1000000,0x100ffff,0,0x11000);
    add("zero-size",1,0,0,0,0); add("one-byte",1,0,0,0,1); add("unaligned-size",1,0,0,0,0x1001);
    add("commit-only",1,0,0,0,0x1000,MEM_COMMIT); add("reserve-commit",1,0,0,0,0x1000,MEM_RESERVE|MEM_COMMIT);
    add("invalid-flags",1,0,0,0,0x1000,0); add("invalid-protect",1,0,0,0,0x1000,MEM_RESERVE,0);
    add("fixed-zero-requirements",16); add("fixed-nonzero-requirements",16,0,0,0x10000); add("fixed-unaligned",17);
    for (ULONG count : {0u,1u,2u,3u,4u,5u,6u,7u,8u,9u,16u}) add("bad-array-count",18,0,0,0,0x1000,MEM_RESERVE,PAGE_READWRITE,count);
    for (const auto& c : cases) {
        MEM_ADDRESS_REQUIREMENTS req{reinterpret_cast<void*>(c.low),reinterpret_cast<void*>(c.high),c.alignment};
        alignas(16) MEM_EXTENDED_PARAMETER params[32]{};
        params[0].Type=MemExtendedParameterAddressRequirements; params[0].Pointer=&req;
        params[1]=params[0];
        MEM_EXTENDED_PARAMETER* input=params; ULONG count=c.count;
        alignas(16) unsigned char param_bytes[64]{}, req_bytes[64]{};
        void* base=nullptr; SIZE_T size=c.size;
        switch(c.mode) {
        case 0: input=nullptr; count=0; break;
        case 2: input=nullptr; break;
        case 3: input=reinterpret_cast<MEM_EXTENDED_PARAMETER*>(1); break;
        case 4: params[0].Pointer=nullptr; break;
        case 5: params[0].Pointer=reinterpret_cast<void*>(1); break;
        case 6: params[0].Type=255; break;
        case 7: count=2; break;
        case 8: params[0].Type=MemExtendedParameterNumaNode; params[0].ULong64=0; break;
        case 9: params[0].Type=MemExtendedParameterNumaNode; params[0].ULong64=255; break;
        case 10: params[0].Type=MemExtendedParameterAttributeFlags; params[0].ULong64=0; break;
        case 11: count=2; params[1].Type=MemExtendedParameterNumaNode; params[1].ULong64=0; break;
        case 12: params[0].Reserved=1; break;
        case 13: memcpy(param_bytes+1,params,sizeof(params[0])); input=reinterpret_cast<MEM_EXTENDED_PARAMETER*>(param_bytes+1); break;
        case 14: input=reinterpret_cast<MEM_EXTENDED_PARAMETER*>(1); count=0; break;
        case 15: memcpy(req_bytes+1,&req,sizeof(req)); params[0].Pointer=req_bytes+1; break;
        case 16: base=reinterpret_cast<void*>(0x20000000); break;
        case 17: base=reinterpret_cast<void*>(0x20000001); break;
        case 18: input=reinterpret_cast<MEM_EXTENDED_PARAMETER*>(1); break;
        }
        DWORD exception=0; LONG status=guarded_allocate(allocate,&base,&size,c.flags,c.protect,input,count,&exception);
        printf("case=%s width=%zu mode=%d count=%lu low=%llX high=%llX align=%llX requested=%llX flags=%08lX protect=%08lX status=%08lX exception=%08lX base=%llX size=%llX",
            c.name,sizeof(void*),c.mode,count,static_cast<unsigned long long>(c.low),static_cast<unsigned long long>(c.high),static_cast<unsigned long long>(c.alignment),static_cast<unsigned long long>(c.size),c.flags,c.protect,status,exception,static_cast<unsigned long long>(reinterpret_cast<ULONG_PTR>(base)),static_cast<unsigned long long>(size));
        if (status>=0 && !exception) {
            MEMORY_BASIC_INFORMATION info{}; SIZE_T queried=VirtualQuery(base,&info,sizeof(info));
            printf(" query=%zu state=%08lX region=%llX",queried,info.State,static_cast<unsigned long long>(info.RegionSize));
            SIZE_T zero=0; LONG freed=release(reinterpret_cast<HANDLE>(LONG_PTR(-1)),&base,&zero,MEM_RELEASE);
            printf(" freed=%08lX",freed); if(freed<0) return 2;
        }
        putchar('\n');
    }
    return 0;
}
