#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <stdint.h>
typedef struct {HANDLE process,thread;} CID;
typedef NTSTATUS(NTAPI *OpenFn)(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES,CID*);
typedef NTSTATUS(NTAPI *QueryFn)(HANDLE,ULONG,PVOID,ULONG,PULONG);
static DWORD WINAPI done(void *unused){(void)unused;return 37;}
int main(void){
 OpenFn open=(OpenFn)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtOpenThread");
 QueryFn query=(QueryFn)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtQueryObject");
 DWORD masks[]={2,0x1000,0x1002,0x800,GENERIC_EXECUTE,GENERIC_READ};
 for(unsigned n=0;n<6;++n){
  DWORD tid=0;HANDLE original=CreateThread(NULL,0,done,NULL,CREATE_SUSPENDED,&tid);
  if(!original)return 90;
  OBJECT_ATTRIBUTES oa={0};oa.Length=sizeof(oa);CID cid={(HANDLE)(ULONG_PTR)GetCurrentProcessId(),(HANDLE)(ULONG_PTR)tid};
  HANDLE opened=NULL;NTSTATUS status=open(&opened,masks[n],&oa,&cid);if(status!=0||!opened)return 91;
  ULONG info[14]={0};if(query(opened,0,info,sizeof(info),NULL)!=0)return 92;
  SetLastError(0x12345678);DWORD suspended=SuspendThread(opened);DWORD suspend_error=GetLastError();
  SetLastError(0x12345678);DWORD resumed=ResumeThread(opened);DWORD resume_error=GetLastError();
  for(unsigned i=0;i<8;++i){DWORD previous=ResumeThread(original);if(previous==0xffffffff)return 93;if(previous<=1)break;}
  if(WaitForSingleObject(original,10000)!=WAIT_OBJECT_0)return 94;
  DWORD exit=0;if(!GetExitCodeThread(original,&exit)||exit!=37)return 95;
  printf("{\"access\":%lu,\"grant\":%lu,\"suspended\":%lu,\"suspend_error\":%lu,\"resumed\":%lu,\"resume_error\":%lu}\n",masks[n],info[1],suspended,suspend_error,resumed,resume_error);
  CloseHandle(opened);CloseHandle(original);
 }
 return 0;
}
