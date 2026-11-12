#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
int main() {
    auto base = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(L"ntdll.dll"));
    if (!base) return 11;
    auto dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(base);
    auto pe = reinterpret_cast<const IMAGE_NT_HEADERS *>(base + dos->e_lfanew);
    const auto size = pe->OptionalHeader.SizeOfImage;
    auto range = [&](std::uint64_t rva, std::uint64_t bytes) { return rva <= size && bytes <= size-rva; };
    auto word = [&](std::uint64_t rva) { DWORD v=0; std::memcpy(&v,reinterpret_cast<const void *>(base+rva),4); return v; };
    auto load = pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
    if (!range(load.VirtualAddress,208) || load.Size < 208) return 12;
    std::uintptr_t metadata=0;
    std::memcpy(&metadata,reinterpret_cast<const void *>(base+load.VirtualAddress+200),8);
    if (metadata<base || !range(metadata-base,92)) return 13;
    const auto at=metadata-base;
    const auto redirects=word(at+16), count=word(at+52), entries=word(at+12), entry_count=word(at+48);
    if (count>65536 || entry_count>65536 || !range(redirects,8ull*count) || !range(entries,12ull*entry_count)) return 14;
    std::printf("{\"kind\":\"metadata\",\"machine\":%u,\"version\":%lu,\"redirections\":%lu,\"entries\":%lu}\n", unsigned(pe->FileHeader.Machine),word(at),count,entry_count);
    const char *names[]={"KiUserExceptionDispatcher","KiUserCallbackDispatcher","LdrInitializeThunk","RtlUserThreadStart"};
    for (auto name:names) {
        const auto address=reinterpret_cast<std::uintptr_t>(GetProcAddress(reinterpret_cast<HMODULE>(base),name));
        if (!address || address<base || !range(address-base,1)) return 15;
        const auto rva=address-base;
        std::printf("{\"name\":\"%s\",\"rva\":%llu,\"redirects\":[",name,static_cast<unsigned long long>(rva));
        unsigned found=0;
        for (DWORD i=0;i<count;++i) if (word(redirects+8ull*i)==rva) std::printf("%s%lu",found++ ? ",":"",word(redirects+8ull*i+4));
        std::printf("],\"entry_ranges\":["); found=0;
        for (DWORD i=0;i<entry_count;++i) {auto row=entries+12ull*i;auto first=word(row),last=word(row+4);if(first<=rva && rva<last) std::printf("%s[%lu,%lu,%lu]",found++ ? ",":"",first,last,word(row+8));}
        std::printf("]}\n");
        for (DWORD i=0;i<count;++i) if (word(redirects+8ull*i)==rva) {
            auto dest=word(redirects+8ull*i+4); if (!range(dest,256)) return 16;
            std::printf("{\"kind\":\"native_entry\",\"name\":\"%s\",\"rva\":%lu,\"code\":\"",name,dest);
            auto bytes=reinterpret_cast<const unsigned char *>(base+dest);
            for(unsigned j=0;j<256;++j) std::printf("%02x",bytes[j]);
            std::printf("\"}\n");
        }
    }
    return 0;
}
