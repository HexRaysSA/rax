#include <windows.h>
#include <winternl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { HANDLE process, thread; } CID;
typedef NTSTATUS(NTAPI *OpenFn)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, CID *);
typedef NTSTATUS(NTAPI *QueryFn)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef struct {
  ULONG attributes, granted, handles, pointers;
  ULONG rest[10];
} BASIC;

static DWORD WINAPI worker(void *event) {
  return WaitForSingleObject(event, INFINITE) == WAIT_OBJECT_0 ? 37 : 38;
}

static DWORD protection(void *p) {
  MEMORY_BASIC_INFORMATION m;
  return VirtualQuery(p, &m, sizeof(m)) ? m.Protect : 0;
}

int main(int argc, char **argv) {
  int which = argc > 1 ? atoi(argv[1]) : 0;
  OpenFn open = (OpenFn)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtOpenThread");
  QueryFn query = (QueryFn)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryObject");
  unsigned char *pages = VirtualAlloc(NULL, 24576, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
  if (!open || !query || !pages) return 90;
  memset(pages, 0xcc, 24576);
  HANDLE *output = (HANDLE *)(pages + 128);
  OBJECT_ATTRIBUTES *oa = (OBJECT_ATTRIBUTES *)(pages + 4096 + 128);
  CID *cid = (CID *)(pages + 8192 + 128);
  OBJECT_ATTRIBUTES original;
  CID identity;
  DWORD access = THREAD_QUERY_LIMITED_INFORMATION, old;
  DWORD pid = GetCurrentProcessId(), tid = GetCurrentThreadId();
  HANDLE event = NULL, peer = NULL;
  UNICODE_STRING name = {0};
  SECURITY_QUALITY_OF_SERVICE qos = {sizeof(qos), SecurityImpersonation, SECURITY_STATIC_TRACKING, FALSE};
  memset(&original, 0, sizeof(original)); original.Length = sizeof(original);
  identity.process = (HANDLE)(ULONG_PTR)pid;
  identity.thread = (HANDLE)(ULONG_PTR)tid;
  memcpy(oa, &original, sizeof(original)); memcpy(cid, &identity, sizeof(identity));
  if (which >= 40 && which <= 42) {
    event = CreateEventW(NULL, TRUE, FALSE, NULL);
    peer = CreateThread(NULL, 0, worker, event, 0, &tid);
    if (!event || !peer) return 91;
    cid->thread = (HANDLE)(ULONG_PTR)tid;
    if (which >= 41) { SetEvent(event); if (WaitForSingleObject(peer, 10000) != WAIT_OBJECT_0) return 92; }
    if (which == 42) { CloseHandle(peer); peer = NULL; }
  }
  if (which >= 148 && which <= 153) {
    HANDLE token = NULL;
    TOKEN_PRIVILEGES privileges;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) return 94;
    privileges.PrivilegeCount = 1;
    if (!LookupPrivilegeValueW(NULL, L"SeSecurityPrivilege", &privileges.Privileges[0].Luid)) return 95;
    privileges.Privileges[0].Attributes = 0;
    if (!AdjustTokenPrivileges(token, FALSE, &privileges, 0, NULL, NULL)) return 96;
    CloseHandle(token);
    DWORD values[] = {0x01000000,0x03000000,0xffffffff,0x011fffff,0x01000001,0x02000001};
    access = values[which-148];
  }
  if (which >= 154 && which < 170) {
    unsigned visible = (which-154)*4;
    oa = (OBJECT_ATTRIBUTES *)(pages + 16384 - visible);
    memcpy(oa, &original, sizeof(original));
    VirtualProtect(pages+16384,4096,PAGE_NOACCESS,&old);
  }
  if (which >= 170 && which < 186) {
    unsigned visible = (which-170)*2;
    cid = (CID *)(pages + 16384 - visible);
    memcpy(cid, &identity, sizeof(identity));
    VirtualProtect(pages+16384,4096,PAGE_NOACCESS,&old);
  }
  if (which >= 186 && which < 202) {
    unsigned char *sd = pages + 16384 + 128;
    memset(sd,0,64);
    oa->SecurityDescriptor = sd;
    if (which != 186) sd[0]=SECURITY_DESCRIPTOR_REVISION;
    if (which == 188) sd[2]=0x04;
    if (which == 189) sd[3]=0x80;
    if (which == 190) { sd[2]=0x04;sd[3]=0x80; }
    if (which == 191) { sd[2]=0xff;sd[3]=0xff; }
    if (which == 192) sd[1]=0xff;
    if (which == 193) oa->SecurityDescriptor = sd+1;
    if (which == 194) VirtualProtect(pages+16384,4096,PAGE_NOACCESS,&old);
    if (which == 195) VirtualProtect(pages+16384,4096,PAGE_READWRITE|PAGE_GUARD,&old);
    if (which == 196) { sd[3]=0x80;*(DWORD *)(sd+4)=0xfffffff0; }
    if (which == 197) { sd[3]=0x80;*(DWORD *)(sd+8)=0xfffffff0; }
    if (which == 198) { sd[2]=4;sd[3]=0x80;*(DWORD *)(sd+16)=0xfffffff0; }
    if (which == 199) oa->Length=0;
    if (which == 200) cid=NULL;
    if (which == 201) output=NULL;
  }
  if (which >= 202 && which < 214) {
    oa->SecurityQualityOfService=&qos;
    if (which < 208) qos.Length = (which-202)*4;
    if (which == 208) qos.ImpersonationLevel=(SECURITY_IMPERSONATION_LEVEL)0xffffffff;
    if (which == 209) qos.ContextTrackingMode=0xff;
    if (which == 210) qos.EffectiveOnly=0xff;
    if (which == 211) oa->SecurityQualityOfService=pages+16384;
    if (which == 212) { memcpy(pages+16384,&qos,sizeof(qos));oa->SecurityQualityOfService=pages+16384;VirtualProtect(pages+16384,4096,PAGE_NOACCESS,&old); }
    if (which == 213) { memcpy(pages+16384,&qos,sizeof(qos));oa->SecurityQualityOfService=pages+16384;VirtualProtect(pages+16384,4096,PAGE_READWRITE|PAGE_GUARD,&old); }
  }
  if (which >= 240 && which < 248) {
    HANDLE token = NULL;
    TOKEN_PRIVILEGES privileges;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY, &token)) return 94;
    privileges.PrivilegeCount=1;
    for (int i=0;i<2;++i) {
      if (!LookupPrivilegeValueW(NULL,i==0?L"SeSecurityPrivilege":L"SeDebugPrivilege",&privileges.Privileges[0].Luid)) return 95;
      privileges.Privileges[0].Attributes=0;
      SetLastError(0);
      if (!AdjustTokenPrivileges(token,FALSE,&privileges,0,NULL,NULL) || GetLastError()!=0) return 96;
    }
    CloseHandle(token);
    DWORD masks[]={0x01000000,0x03000000,0xffffffff,0x011fffff,0x01000001,0x02000001,0,0x00400000};
    access=masks[which-240];
  }
  if (which>=248 && which<264) oa->Attributes=(DWORD)1<<(which-248+16);
  if (which>=264 && which<270) {
    if (which<267) cid->thread=(HANDLE)((ULONG_PTR)tid+(which-264)+1);
    else cid->process=(HANDLE)((ULONG_PTR)pid+(which-267)+1);
  }
  if (which>=270 && which<274) {
    unsigned char *sd=pages+16384+128;
    memset(sd,0,64);sd[0]=1;oa->SecurityDescriptor=sd;
    *(DWORD *)(sd+4+(which-270)*4)=1;
    if(which>=272)sd[2]=which==272?0x10:0x04;
  }
  if (which>=274 && which<282) {
    oa->ObjectName=&name;
    name.Buffer=(PWSTR)(pages+16384+128);
    name.Length=which==274?1:which==275?2:which==276?3:which==277?65534:which==278?65535:0;
    name.MaximumLength=name.Length;
    if(which==279)name.Buffer=(PWSTR)1;
    if(which==280){name.Length=2;name.Buffer=(PWSTR)1;}
    if(which==281){name.Length=2;VirtualProtect(pages+16384,4096,PAGE_READWRITE|PAGE_GUARD,&old);}
  }
  switch (which) {
  case 1: access = THREAD_ALL_ACCESS; break;
  case 2: access = 0; break;
  case 3: access = MAXIMUM_ALLOWED; break;
  case 4: access = GENERIC_READ; break;
  case 5: access = GENERIC_WRITE; break;
  case 6: access = GENERIC_EXECUTE; break;
  case 7: access = GENERIC_ALL; break;
  case 8: access = ACCESS_SYSTEM_SECURITY; break;
  case 9: access = ACCESS_SYSTEM_SECURITY | MAXIMUM_ALLOWED; break;
  case 10: access = 0x00400000; break;
  case 11: access = 0x00800000; break;
  case 12: access = 0x04000000; break;
  case 13: access = 0x08000000; break;
  case 14: access = 0xffffffff; break;
  case 15: access = 0x1000; break;
  case 16: access = 0x2000; break;
  case 17: access = 0x4000; break;
  case 18: access = 0x8000; break;
  case 19: access = THREAD_QUERY_INFORMATION; break;
  case 20: access = THREAD_SET_INFORMATION; break;
  case 21: cid->process = NULL; break;
  case 22: cid->process = (HANDLE)(ULONG_PTR)(pid + 1); break;
  case 23: cid->process = (HANDLE)(LONG_PTR)-1; break;
  case 24: cid->thread = NULL; break;
  case 25: cid->thread = (HANDLE)(LONG_PTR)-2; break;
  case 26: cid->thread = (HANDLE)(ULONG_PTR)0x7ffffffc; break;
  case 27: cid = NULL; break;
  case 28: cid = (CID *)1; break;
  case 29: cid = (CID *)((unsigned char *)cid + 1); memcpy(cid, &identity, sizeof(identity)); break;
  case 30: cid = (CID *)((unsigned char *)cid + 4); memcpy(cid, &identity, sizeof(identity)); break;
  case 31: cid->process = (HANDLE)((ULONG_PTR)pid | ((uint64_t)1 << 32)); break;
  case 32: cid->thread = (HANDLE)((ULONG_PTR)tid | ((uint64_t)1 << 32)); break;
  case 33: oa = NULL; break;
  case 34: oa = (OBJECT_ATTRIBUTES *)1; break;
  case 35: oa = (OBJECT_ATTRIBUTES *)((unsigned char *)oa + 1); memcpy(oa, &original, sizeof(original)); break;
  case 36: oa = (OBJECT_ATTRIBUTES *)((unsigned char *)oa + 4); memcpy(oa, &original, sizeof(original)); break;
  case 37: oa->Length = 0; break;
  case 38: oa->Length = sizeof(original) - 1; break;
  case 39: oa->Length = sizeof(original) + 1; break;
  case 43: oa->ObjectName = &name; break;
  case 44: oa->ObjectName = (UNICODE_STRING *)1; break;
  case 45: oa->RootDirectory = (HANDLE)0x1234; break;
  case 46: oa->SecurityDescriptor = (void *)1; break;
  case 47: oa->SecurityQualityOfService = (void *)1; break;
  case 48: oa->SecurityQualityOfService = &qos; break;
  case 49: oa->Attributes = OBJ_INHERIT; break;
  case 50: oa->Attributes = OBJ_CASE_INSENSITIVE; break;
  case 51: oa->Attributes = OBJ_KERNEL_HANDLE; break;
  case 52: oa->Attributes = 0x400; break;
  case 53: oa->Attributes = 0x2000; break;
  case 54: oa->Attributes = 0x80; break;
  case 55: oa->Attributes = 1; break;
  case 56: oa->Attributes = 0xffffffff; break;
  case 57: output = NULL; break;
  case 58: output = (HANDLE *)1; break;
  case 59: output = (HANDLE *)((unsigned char *)output + 1); break;
  case 60: output = (HANDLE *)((unsigned char *)output + 4); break;
  case 61: VirtualProtect(pages, 4096, PAGE_READONLY, &old); break;
  case 62: VirtualProtect(pages, 4096, PAGE_NOACCESS, &old); break;
  case 63: VirtualProtect(pages, 4096, PAGE_READWRITE | PAGE_GUARD, &old); break;
  case 64: VirtualProtect(pages, 4096, PAGE_READONLY | PAGE_GUARD, &old); break;
  case 65: output = (HANDLE *)(pages + 4096 - sizeof(HANDLE) / 2); VirtualProtect(pages + 4096, 4096, PAGE_NOACCESS, &old); break;
  case 66: output = (HANDLE *)(pages + 4096 - sizeof(HANDLE) / 2); VirtualProtect(pages + 4096, 4096, PAGE_READWRITE | PAGE_GUARD, &old); break;
  case 67: output = (HANDLE *)oa; break;
  case 68: output = (HANDLE *)cid; break;
  case 69: output = &cid->thread; break;
  case 70: output = (HANDLE *)&oa->Attributes; break;
  case 71: VirtualProtect(pages + 4096, 4096, PAGE_NOACCESS, &old); break;
  case 72: VirtualProtect(pages + 4096, 4096, PAGE_READWRITE | PAGE_GUARD, &old); break;
  case 73: VirtualProtect(pages + 8192, 4096, PAGE_NOACCESS, &old); break;
  case 74: VirtualProtect(pages + 8192, 4096, PAGE_READWRITE | PAGE_GUARD, &old); break;
  case 75: output = NULL; cid = NULL; break;
  case 76: output = NULL; oa = NULL; break;
  case 77: output = (HANDLE *)1; cid = NULL; break;
  case 78: output = (HANDLE *)1; oa = (OBJECT_ATTRIBUTES *)1; break;
  case 79: oa = (OBJECT_ATTRIBUTES *)1; cid = NULL; break;
  case 80: oa = NULL; cid = (CID *)1; break;
  case 81: oa->Length = 0; cid = (CID *)1; break;
  case 82: oa->ObjectName = (UNICODE_STRING *)1; cid = NULL; break;
  case 83: cid->thread = NULL; output = NULL; break;
  case 84: cid->thread = NULL; VirtualProtect(pages, 4096, PAGE_READWRITE | PAGE_GUARD, &old); break;
  case 85: access = 0xffffffff; cid->thread = NULL; break;
  case 86: access = ACCESS_SYSTEM_SECURITY; cid->thread = NULL; break;
  case 87: oa->Attributes = 0xffffffff; cid->thread = NULL; break;
  case 88: oa->SecurityDescriptor = (void *)1; cid->thread = NULL; break;
  case 89: oa->SecurityQualityOfService = (void *)1; cid->thread = NULL; break;
  case 90: oa->ObjectName = (UNICODE_STRING *)1; cid->thread = NULL; break;
  case 91: oa->RootDirectory = (HANDLE)0x1234; cid->thread = NULL; break;
  case 92: access = 0xffffffff; oa->Length = 0; break;
  case 93: access = 0xffffffff; oa->SecurityQualityOfService = (void *)1; break;
  case 94: oa->Attributes = 0xffffffff; oa->Length = 0; break;
  case 95: oa->Attributes = 0xffffffff; cid = (CID *)1; break;
  case 96: cid = (CID *)(pages + 12288 - sizeof(CID) / 2); memcpy(cid, &identity, sizeof(identity)); VirtualProtect(pages + 12288, 4096, PAGE_NOACCESS, &old); break;
  case 97: oa = (OBJECT_ATTRIBUTES *)(pages + 8192 - sizeof(OBJECT_ATTRIBUTES) / 2); memcpy(oa, &original, sizeof(original)); VirtualProtect(pages + 8192, 4096, PAGE_NOACCESS, &old); break;
  case 98: oa->Length = 0; VirtualProtect(pages + 8192, 4096, PAGE_READWRITE | PAGE_GUARD, &old); break;
  case 99: output = NULL; oa->Length = 0; break;
  case 214: VirtualProtect(pages,4096,PAGE_NOACCESS,&old);VirtualProtect(pages+4096,4096,PAGE_READWRITE|PAGE_GUARD,&old);break;
  case 215: VirtualProtect(pages,4096,PAGE_READONLY,&old);VirtualProtect(pages+8192,4096,PAGE_READWRITE|PAGE_GUARD,&old);break;
  case 216: output=NULL;VirtualProtect(pages+4096,4096,PAGE_READWRITE|PAGE_GUARD,&old);break;
  case 217: oa=NULL;VirtualProtect(pages+8192,4096,PAGE_READWRITE|PAGE_GUARD,&old);break;
  case 218: oa->Length=0;VirtualProtect(pages,4096,PAGE_READWRITE|PAGE_GUARD,&old);break;
  case 219: cid=NULL;VirtualProtect(pages+4096,4096,PAGE_READWRITE|PAGE_GUARD,&old);break;
  case 220: oa->ObjectName=(UNICODE_STRING *)1;VirtualProtect(pages+8192,4096,PAGE_READWRITE|PAGE_GUARD,&old);break;
  case 221: access=0;cid=NULL;break;
  case 222: access=0;oa->Attributes=0xffffffff;break;
  case 223: access=0;output=NULL;break;
  case 224: oa->ObjectName=&name;cid=NULL;break;
  case 225: oa->ObjectName=(UNICODE_STRING *)1;cid=NULL;break;
  case 226: oa->ObjectName=&name;oa->Attributes=0xffffffff;break;
  case 227: oa->RootDirectory=(HANDLE)0x1234;cid=NULL;break;
  case 228: oa->Attributes=0x10;cid=NULL;break;
  case 229: oa->Attributes=0x10;oa->ObjectName=(UNICODE_STRING *)1;break;
  case 230: oa->SecurityDescriptor=(void *)1;VirtualProtect(pages+8192,4096,PAGE_READWRITE|PAGE_GUARD,&old);break;
  case 231: oa->SecurityQualityOfService=(void *)1;VirtualProtect(pages+8192,4096,PAGE_READWRITE|PAGE_GUARD,&old);break;
  case 232: output=(HANDLE *)(pages+4096-sizeof(HANDLE));VirtualProtect(pages+4096,4096,PAGE_NOACCESS,&old);oa=(OBJECT_ATTRIBUTES *)(pages+12288+128);memcpy(oa,&original,sizeof(original));break;
  case 233: output=(HANDLE *)(pages+4096-sizeof(HANDLE)+1);VirtualProtect(pages+4096,4096,PAGE_NOACCESS,&old);oa=(OBJECT_ATTRIBUTES *)(pages+12288+128);memcpy(oa,&original,sizeof(original));break;
  case 234: output=(HANDLE *)(pages+4096-1);VirtualProtect(pages+4096,4096,PAGE_READONLY|PAGE_GUARD,&old);oa=(OBJECT_ATTRIBUTES *)(pages+12288+128);memcpy(oa,&original,sizeof(original));break;
  case 235: output=(HANDLE *)(pages+4096-1);VirtualProtect(pages+4096,4096,PAGE_READWRITE|PAGE_GUARD,&old);oa=(OBJECT_ATTRIBUTES *)(pages+12288+128);memcpy(oa,&original,sizeof(original));break;
  case 236: access=0;break;
  case 237: access=0x00200000;break;
  case 238: access=0x02000000|0x01000000;break;
  case 239: access=0x02000000|0x00400000;break;
  default:
    if (which >= 100 && which < 132) access = (DWORD)1 << (which - 100);
    if (which >= 132 && which < 148) oa->Attributes = (DWORD)1 << (which - 132);
    break;
  }
  DWORD before = 0, after = 0, last_error, raised = 0;
  GetProcessHandleCount(GetCurrentProcess(), &before);
  NTSTATUS status = (NTSTATUS)0xdeadbeef;
  SetLastError(0x12345678);
  __try { status = open(output, access, oa, cid); }
  __except(EXCEPTION_EXECUTE_HANDLER) { raised = GetExceptionCode(); }
  last_error = GetLastError();
  GetProcessHandleCount(GetCurrentProcess(), &after);
  DWORD protections[6];
  for (int i = 0; i < 6; ++i) { protections[i] = protection(pages + i * 4096); VirtualProtect(pages + i * 4096, 4096, PAGE_READWRITE, &old); }
  HANDLE result = NULL;
  BOOL readable = (ULONG_PTR)output >= (ULONG_PTR)pages && (ULONG_PTR)output + sizeof(HANDLE) <= (ULONG_PTR)pages + 24576;
  if (readable) memcpy(&result, output, sizeof(result));
  BASIC basic = {0};
  NTSTATUS queried = result && result != (HANDLE)(LONG_PTR)-1 ? query(result, 0, &basic, sizeof(basic), NULL) : (NTSTATUS)0xc0000008;
  DWORD target = queried == 0 ? GetThreadId(result) : 0;
  printf("{\"case\":%d,\"pointer_size\":%u,\"access\":%lu,\"status\":%lu,\"raised\":%lu,\"last_error\":%lu,\"handle_delta\":%ld,\"query_status\":%lu,\"grant\":%lu,\"handle_attributes\":%lu,\"target_matches\":%s,\"out_offset\":%lld,\"out_hex\":\"", which, (unsigned)sizeof(void *), access, (ULONG)status, raised, last_error, (LONG)after-(LONG)before, (ULONG)queried, basic.granted, basic.attributes, target == tid ? "true" : "false", readable ? (long long)((unsigned char *)output-pages) : output == NULL ? -1LL : -2LL);
  if (readable) for (unsigned i=0;i<sizeof(HANDLE);++i) printf("%02x", ((unsigned char *)output)[i]);
  printf("\",\"protections\":[%lu,%lu,%lu,%lu,%lu,%lu]}\n",protections[0],protections[1],protections[2],protections[3],protections[4],protections[5]);
  if (queried == 0) CloseHandle(result);
  if (peer) { SetEvent(event); if (WaitForSingleObject(peer, 10000) != WAIT_OBJECT_0) return 93; CloseHandle(peer); }
  if (event) CloseHandle(event);
  VirtualFree(pages, 0, MEM_RELEASE);
  return 0;
}
