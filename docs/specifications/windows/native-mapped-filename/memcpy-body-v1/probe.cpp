#include <windows.h>
#include <cstdint>
#include <cstdio>
#ifndef _M_ARM64
#error Native ARM64 observer required
#endif
int main(int argc,char** argv) {
 if(argc!=2)return 2;
 USHORT process=0,native=0;
 if(!IsWow64Process2(GetCurrentProcess(),&process,&native)||process!=0||native!=0xAA64)return 3;
 auto module=GetModuleHandleW(L"ntdll.dll");
 auto base=reinterpret_cast<const unsigned char*>(module);
 auto dos=reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
 auto nt=reinterpret_cast<const IMAGE_NT_HEADERS64*>(base+dos->e_lfanew);
 const auto size=nt->OptionalHeader.SizeOfImage;
 auto address=reinterpret_cast<const unsigned char*>(GetProcAddress(module,"memcpy"));
 if(!address)return 4;
 std::printf("{\"process_machine\":%u,\"native_machine\":%u,\"image_machine\":%u,\"size_of_image\":%lu}\n",unsigned(process),unsigned(native),unsigned(nt->FileHeader.Machine),size);
 unsigned hops=0;
 for(;hops<5;++hops) {
  if(address<base||address+16>base+size)return 5;
  std::uint32_t word=std::uint32_t(address[0])|(std::uint32_t(address[1])<<8)|(std::uint32_t(address[2])<<16)|(std::uint32_t(address[3])<<24);
  if((word&0xFC000000u)!=0x14000000u)break;
  std::int64_t delta=word&0x03FFFFFFu;
  if(delta&(std::int64_t(1)<<25))delta-=std::int64_t(1)<<26;
  auto target=address+delta*4;
  if(target<base||target>=base+size||target==address)return 6;
  std::printf("{\"rva\":%llu,\"word\":%lu,\"target_rva\":%llu}\n",static_cast<unsigned long long>(address-base),static_cast<unsigned long>(word),static_cast<unsigned long long>(target-base));
  address=target;
 }
 if(hops==5||address+2048>base+size)return 7;
 FILE* out=nullptr;
 if(fopen_s(&out,argv[1],"wb")||!out)return 8;
 const auto written=std::fwrite(address,1,2048,out);
 const auto closed=std::fclose(out);
 if(written!=2048||closed)return 9;
 std::printf("{\"body_rva\":%llu,\"bytes\":2048,\"hops\":%u}\n",static_cast<unsigned long long>(address-base),hops);
 return 0;
}
