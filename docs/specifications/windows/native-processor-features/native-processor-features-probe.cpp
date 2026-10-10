#include <windows.h>
#include <cstdio>
#include <cstring>
#include <initializer_list>
using Query = LONG(NTAPI*)(ULONG, void*, ULONG, ULONG*);
int main() {
    setvbuf(stdout,nullptr,_IONBF,0);
    auto query = reinterpret_cast<Query>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation"));
    auto pages = static_cast<unsigned char*>(VirtualAlloc(nullptr, 8192, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    if (!query || !pages) return 1;
    DWORD old;
    for (unsigned length : {0u, 1u, 4u, 8u, 12u, 15u, 16u, 17u, 20u, 24u, 31u, 32u, 33u, 48u, 64u}) {
        memset(pages, 0xA5, 8192); ULONG returned = 0xA5A5A5A5;
        auto status = query(250, pages, length, &returned);
        printf("pointer=%zu length=%u status=%08lX returned=%08lX bytes=", sizeof(void*), length, status, returned);
        for (unsigned i=0; i<24; ++i) printf("%02X",pages[i]);
        printf("\n");
    }
    for (unsigned role=0; role<14; ++role) {
        VirtualProtect(pages,8192,PAGE_READWRITE,&old); memset(pages,0xA5,8192);
        void* out=pages; ULONG length=16; auto returned=reinterpret_cast<ULONG*>(pages+4096);
        switch(role) {
        case 0: out=pages+1;break;
        case 1: out=pages+1;returned=reinterpret_cast<ULONG*>(1);break;
        case 2: out=nullptr;break;
        case 3: out=nullptr;length=0;break;
        case 4: returned=nullptr;break;
        case 5: returned=reinterpret_cast<ULONG*>(pages+4097);break;
        case 6: VirtualProtect(pages,4096,PAGE_READONLY,&old);length=15;break;
        case 7: VirtualProtect(pages,4096,PAGE_READWRITE|PAGE_GUARD,&old);break;
        case 8: VirtualProtect(pages+4096,4096,PAGE_READWRITE|PAGE_GUARD,&old);length=15;break;
        case 9: VirtualProtect(pages,4096,PAGE_READWRITE|PAGE_GUARD,&old);VirtualProtect(pages+4096,4096,PAGE_READONLY,&old);break;
        case 10: VirtualProtect(pages+4096,4096,PAGE_READONLY,&old);break;
        case 11: returned=reinterpret_cast<ULONG*>(pages);break;
        case 12: out=pages+4080;length=17;VirtualProtect(pages+4096,4096,PAGE_READONLY,&old);returned=nullptr;break;
        case 13: out=pages+4080;length=17;VirtualProtect(pages+4096,4096,PAGE_READWRITE|PAGE_GUARD,&old);returned=nullptr;break;
        }
        auto status=query(250,out,length,returned); MEMORY_BASIC_INFORMATION a{},b{};
        VirtualQuery(pages,&a,sizeof(a)); VirtualQuery(pages+4096,&b,sizeof(b));
        VirtualProtect(pages,8192,PAGE_READWRITE,&old);
        printf("pointer=%zu role=%u length=%lu status=%08lX output_protect=%08lX returned_protect=%08lX returned=%08lX prefix=",sizeof(void*),role,length,status,a.Protect,b.Protect,*reinterpret_cast<ULONG*>(pages+4096));
        for (unsigned i=0; i<20; ++i) printf("%02X",pages[i]); printf("\n");
    }
    VirtualProtect(pages,8192,PAGE_READWRITE,&old); memset(pages,0,8192);ULONG returned=0;
    auto status=query(250,pages,16,&returned);
    printf("pointer=%zu bitmap_status=%08lX returned=%lu\n",sizeof(void*),status,returned);
    for (unsigned i=0;i<128;++i) {
        bool bitmap=(pages[i/8] & (1u<<(i%8))) !=0;
        BOOL api=IsProcessorFeaturePresent(64+i);
        if(bitmap || api) printf("feature=%u bitmap=%u api=%u\n",64+i,unsigned(bitmap),unsigned(api!=0));
    }
    for(unsigned i=0;i<64;++i) if(IsProcessorFeaturePresent(i)) printf("shared_feature=%u api=1\n",i);
    VirtualFree(pages,0,MEM_RELEASE);
}
