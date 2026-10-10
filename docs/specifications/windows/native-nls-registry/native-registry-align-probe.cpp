#include <windows.h>
#include <winternl.h>
#include <cstdio>
#include <cstring>
#include <initializer_list>
#include <string>
// Read-only opens/queries of one existing system NLS key. No writes,
// creates, deletes, enumeration of personal data, or privilege changes.
using Open=LONG(NTAPI*)(HANDLE*,ACCESS_MASK,OBJECT_ATTRIBUTES*);
using Query=LONG(NTAPI*)(HANDLE,UNICODE_STRING*,ULONG,void*,ULONG,ULONG*);
using Close=LONG(NTAPI*)(HANDLE);
UNICODE_STRING us(const wchar_t* s){UNICODE_STRING u{};u.Length=USHORT(wcslen(s)*2);u.MaximumLength=u.Length+2;u.Buffer=const_cast<wchar_t*>(s);return u;}
int main(){setvbuf(stdout,nullptr,_IONBF,0);auto n=GetModuleHandleW(L"ntdll.dll");auto open=reinterpret_cast<Open>(GetProcAddress(n,"NtOpenKey"));auto query=reinterpret_cast<Query>(GetProcAddress(n,"NtQueryValueKey"));auto close=reinterpret_cast<Close>(GetProcAddress(n,"NtClose"));printf("pointer=%zu open=%u query=%u ACP=%u OEMCP=%u\n",sizeof(void*),unsigned(open!=nullptr),unsigned(query!=nullptr),GetACP(),GetOEMCP());if(!open||!query||!close)return 1;
 auto name=us(L"\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Nls\\CodePage");OBJECT_ATTRIBUTES a{};a.Length=sizeof(a);a.ObjectName=&name;a.Attributes=0x240;HANDLE key=nullptr;auto status=open(&key,GENERIC_READ,&a);printf("open normal status=%08lX handle=%p attributes_size=%lu\n",status,key,a.Length);if(status<0)return 2;
 auto p=static_cast<unsigned char*>(VirtualAlloc(nullptr,8192,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE));DWORD old;if(!p)return 3;

 for(ULONG cls:{0u,1u,2u,3u,4u,5u})for(ULONG length:{0u,8u,12u,16u,20u,22u,32u,64u})for(unsigned role=0;role<3;++role){VirtualProtect(p,8192,PAGE_READWRITE,&old);memset(p,0xA5,8192);auto value=us(L"ACP");void* output=p+1;ULONG returned=0xA5A5A5A5;HANDLE current=key;if(role==1)current=nullptr;if(role==2)output=p+4;auto status=query(current,&value,cls,output,length,&returned);printf("alignment pointer=%zu class=%lu length=%lu role=%u status=%08lX returned=%08lX bytes=",sizeof(void*),cls,length,role,status,returned);for(unsigned i=0;i<32;++i)printf("%02X",static_cast<unsigned char*>(output)[i]);printf("\n");}
 for(unsigned role=0;role<8;++role){VirtualProtect(p,8192,PAGE_READWRITE,&old);memset(p,0xA5,8192);auto value=us(L"ACP");auto vn=reinterpret_cast<UNICODE_STRING*>(p+1);memcpy(vn,&value,sizeof(value));ULONG returned=0xA5A5A5A5;HANDLE current=key;ULONG cls=2;void* output=p+128;if(role==1)current=nullptr;if(role==2)cls=5;if(role==3){vn->Length=1;}if(role==4){vn->MaximumLength=0;}if(role==5){vn->Buffer=nullptr;}if(role==6){vn->Length=0;vn->Buffer=nullptr;}if(role==7){vn=nullptr;}auto status=query(current,vn,cls,output,64,&returned);printf("name pointer=%zu role=%u status=%08lX returned=%08lX\n",sizeof(void*),role,status,returned);}
 close(key);VirtualFree(p,0,MEM_RELEASE);}
