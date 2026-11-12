#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <cstddef>
int main() {
 auto x=reinterpret_cast<const XSTATE_CONFIGURATION*>(0x7ffe03d8ull);
 std::printf("{\"kind\":\"xstate\",\"structure_size\":%llu,\"enabled\":%llu,\"volatile\":%llu,\"size\":%lu,\"control\":%lu,\"supervisor\":%llu,\"aligned\":%llu,\"all_size\":%lu,\"all_features_at\":%llu,\"user_supervisor\":%llu,\"non_large_size\":%lu,\"api_mask\":%llu}\n",static_cast<unsigned long long>(sizeof(*x)),x->EnabledFeatures,x->EnabledVolatileFeatures,x->Size,x->ControlFlags,x->EnabledSupervisorFeatures,x->AlignedFeatures,x->AllFeatureSize,static_cast<unsigned long long>(offsetof(XSTATE_CONFIGURATION,AllFeatures)),x->EnabledUserVisibleSupervisorFeatures,x->AllNonLargeFeatureSize,GetEnabledXStateFeatures());
 for(unsigned i=0;i<64;++i)if(x->Features[i].Size || x->Features[i].Offset || x->AllFeatures[i])std::printf("{\"feature\":%u,\"offset\":%lu,\"size\":%lu,\"all\":%lu}\n",i,x->Features[i].Offset,x->Features[i].Size,x->AllFeatures[i]);
 using Fn=LONG(NTAPI*)(PVOID,ULONG,PVOID*);auto init=reinterpret_cast<Fn>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"RtlInitializeExtendedContext"));if(!init)return 11;
 alignas(64) unsigned char buffer[4096]={};void* ex=nullptr;auto status=init(buffer,0x100040,&ex);std::printf("{\"kind\":\"initialize\",\"status\":%lu,\"offset\":%lld,\"flags\":%lu,\"chunks\":[",static_cast<DWORD>(status),ex?static_cast<long long>(static_cast<unsigned char*>(ex)-buffer):-1,*reinterpret_cast<DWORD*>(buffer+48));if(ex)for(unsigned i=0;i<6;++i)std::printf("%s%lu",i?",":"",static_cast<DWORD*>(ex)[i]);std::printf("]}\n");return status<0?12:0;
}
