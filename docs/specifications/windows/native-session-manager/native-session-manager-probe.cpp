#include <windows.h>
#include <winternl.h>
#include <cstdio>
#include <cstring>
#include <initializer_list>
// Original read-only oracle for the next exact native-loader registry key.
// No writes, creates, deletes, privilege changes or arbitrary guest names.
using Open=LONG(NTAPI*)(HANDLE*,ACCESS_MASK,OBJECT_ATTRIBUTES*);
using Query=LONG(NTAPI*)(HANDLE,UNICODE_STRING*,ULONG,void*,ULONG,ULONG*);
using Close=LONG(NTAPI*)(HANDLE);
static UNICODE_STRING name(const wchar_t* text){UNICODE_STRING u{};u.Length=USHORT(wcslen(text)*2);u.MaximumLength=u.Length+2;u.Buffer=const_cast<wchar_t*>(text);return u;}
int main(){setvbuf(stdout,nullptr,_IONBF,0);auto n=GetModuleHandleW(L"ntdll.dll");auto open=reinterpret_cast<Open>(GetProcAddress(n,"NtOpenKey"));auto query=reinterpret_cast<Query>(GetProcAddress(n,"NtQueryValueKey"));auto close=reinterpret_cast<Close>(GetProcAddress(n,"NtClose"));if(!open||!query||!close)return 1;auto keyname=name(L"\\Registry\\MACHINE\\System\\CurrentControlSet\\Control\\Session Manager");OBJECT_ATTRIBUTES a{};a.Length=sizeof(a);a.ObjectName=&keyname;a.Attributes=0x240;HANDLE key=nullptr;auto status=open(&key,1,&a);printf("pointer=%zu open=%08lX handle=%p\n",sizeof(void*),status,key);if(status<0)return 2;
for(auto text:{L"GlobalFlag",L"CriticalSectionTimeout",L"HeapSegmentReserve",L"HeapSegmentCommit",L"HeapDeCommitTotalFreeThreshold",L"HeapDeCommitFreeBlockThreshold",L"LowMemoryHeapGrowthPercent",L"SafeDllSearchMode",L"CWDIllegalInDllSearch",L"missing-rax-value"}){auto value=name(text);for(ULONG length:{0u,12u,16u,64u,512u}){alignas(16) unsigned char bytes[512];memset(bytes,0xa5,sizeof(bytes));ULONG returned=0xa5a5a5a5;auto s=query(key,&value,2,bytes,length,&returned);printf("query name=%ls length=%lu status=%08lX returned=%08lX bytes=",text,length,s,returned);for(unsigned i=0;i<64;i++)printf("%02X",bytes[i]);printf("\n");}}
close(key);return 0;}
