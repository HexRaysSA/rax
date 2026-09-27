/* Freestanding PE guest-service contracts. Native Windows execution unknown.
 * Files are confined to a test-only C: mapping by the integration runner. */
typedef unsigned int DWORD;
typedef int LONG;
typedef __UINTPTR_TYPE__ UPTR;
typedef __SIZE_TYPE__ SIZE;
typedef __WCHAR_TYPE__ WCHAR;
typedef void *HANDLE;
typedef union { long long QuadPart; } LARGE_INTEGER;
#if defined(_M_IX86)
#define WINAPI __attribute__((stdcall))
#else
#define WINAPI
#endif
#define DLL __declspec(dllimport)
typedef struct { void *debug; LONG count,recursion; HANDLE owner,sem; UPTR spin; } CS;
typedef struct { UPTR word; } SRW;
typedef struct { UPTR word; } CV;
_Static_assert(sizeof(WCHAR)==2,"UTF-16 units are 16 bits");
_Static_assert(sizeof(CS)==(sizeof(void*)==4?24:40),"critical section ABI");
_Static_assert(sizeof(LARGE_INTEGER)==8,"LARGE_INTEGER is 64 bits");
DLL __declspec(noreturn) void WINAPI ExitProcess(DWORD);
DLL DWORD WINAPI GetLastError(void);
DLL HANDLE WINAPI GetCurrentProcess(void);
DLL DWORD WINAPI GetCurrentThreadId(void);
DLL int WINAPI CloseHandle(HANDLE);
DLL int WINAPI DuplicateHandle(HANDLE,HANDLE,HANDLE,HANDLE*,DWORD,int,DWORD);
DLL int WINAPI GetHandleInformation(HANDLE,DWORD*);
DLL int WINAPI SetHandleInformation(HANDLE,DWORD,DWORD);
DLL DWORD WINAPI TlsAlloc(void);
DLL int WINAPI TlsFree(DWORD);
DLL void *WINAPI TlsGetValue(DWORD);
DLL int WINAPI TlsSetValue(DWORD,void*);
DLL HANDLE WINAPI CreateThread(void*,SIZE,DWORD(WINAPI*)(void*),void*,DWORD,DWORD*);
DLL DWORD WINAPI SuspendThread(HANDLE);
DLL DWORD WINAPI ResumeThread(HANDLE);
DLL int WINAPI TerminateThread(HANDLE,DWORD);
DLL int WINAPI GetExitCodeThread(HANDLE,DWORD*);
DLL void WINAPI Sleep(DWORD);
DLL DWORD WINAPI SleepEx(DWORD,int);
DLL DWORD WINAPI QueueUserAPC(void(WINAPI*)(UPTR),HANDLE,UPTR);
DLL HANDLE WINAPI CreateEventW(void*,int,int,const WCHAR*);
DLL HANDLE WINAPI OpenEventW(DWORD,int,const WCHAR*);
DLL int WINAPI SetEvent(HANDLE);
DLL int WINAPI ResetEvent(HANDLE);
DLL HANDLE WINAPI CreateMutexW(void*,int,const WCHAR*);
DLL int WINAPI ReleaseMutex(HANDLE);
DLL HANDLE WINAPI CreateSemaphoreW(void*,LONG,LONG,const WCHAR*);
DLL int WINAPI ReleaseSemaphore(HANDLE,LONG,LONG*);
DLL DWORD WINAPI WaitForSingleObject(HANDLE,DWORD);
DLL DWORD WINAPI WaitForMultipleObjects(DWORD,const HANDLE*,int,DWORD);
DLL void WINAPI InitializeCriticalSection(CS*);
DLL void WINAPI DeleteCriticalSection(CS*);
DLL void WINAPI EnterCriticalSection(CS*);
DLL int WINAPI TryEnterCriticalSection(CS*);
DLL void WINAPI LeaveCriticalSection(CS*);
DLL void WINAPI InitializeSRWLock(SRW*);
DLL void WINAPI AcquireSRWLockExclusive(SRW*);
DLL void WINAPI ReleaseSRWLockExclusive(SRW*);
DLL void WINAPI AcquireSRWLockShared(SRW*);
DLL void WINAPI ReleaseSRWLockShared(SRW*);
DLL void WINAPI InitializeConditionVariable(CV*);
DLL int WINAPI SleepConditionVariableSRW(CV*,SRW*,DWORD,DWORD);
DLL int WINAPI WaitOnAddress(volatile void*,void*,SIZE,DWORD);
DLL HANDLE WINAPI CreateFileW(const WCHAR*,DWORD,DWORD,void*,DWORD,DWORD,HANDLE);
DLL int WINAPI WriteFile(HANDLE,const void*,DWORD,DWORD*,void*);
DLL int WINAPI ReadFile(HANDLE,void*,DWORD,DWORD*,void*);
DLL int WINAPI GetFileSizeEx(HANDLE,LARGE_INTEGER*);
DLL int WINAPI SetFilePointerEx(HANDLE,LARGE_INTEGER,LARGE_INTEGER*,DWORD);
DLL int WINAPI SetEndOfFile(HANDLE);
DLL int WINAPI FlushFileBuffers(HANDLE);
DLL DWORD WINAPI GetFileType(HANDLE);
DLL int WINAPI DeleteFileW(const WCHAR*);
static CS cs; static SRW srw; static CV cv;
static HANDLE started,phase,ready,mutex;
static DWORD slot,main_tid;
static volatile DWORD apc_value,protected_value;
static void check(int ok,DWORD code) { if(!ok) ExitProcess(code); }
static int valid(HANDLE h) { return h && h!=(HANDLE)(UPTR)-1; }
static void WINAPI apc(UPTR value) { apc_value=(DWORD)value; }
static DWORD WINAPI worker(void *arg) {
    check((UPTR)arg==0xBEEF && GetCurrentThreadId()!=main_tid,101);
    check(!TlsGetValue(slot) && TlsSetValue(slot,(void*)(UPTR)0x456),102);
    check(SetEvent(started),103);
    EnterCriticalSection(&cs);
    check(protected_value==1,104); protected_value=2;
    LeaveCriticalSection(&cs);
    check(SetEvent(phase),105); AcquireSRWLockShared(&srw);
    check(protected_value==2,106); ReleaseSRWLockShared(&srw);
    check(SetEvent(ready),107);
    check(SleepEx(5000,1)==0xC0 && apc_value==0xABCD,108);
    check(TlsGetValue(slot)==(void*)(UPTR)0x456,109);
    return 37;
}
static DWORD WINAPI abandon(void *arg) {
    check(arg==mutex && WaitForSingleObject(mutex,5000)==0,111);
    return 41;
}
static void threads(void) {
    DWORD tid=0,code=0,flags=0;
    check(WaitForSingleObject(GetCurrentProcess(),0)==0x102,32);
    main_tid=GetCurrentThreadId(); slot=TlsAlloc();
    check(slot!=0xFFFFFFFF && TlsSetValue(slot,(void*)(UPTR)0x123),1);
    started=CreateEventW(0,0,0,0); phase=CreateEventW(0,0,0,0); ready=CreateEventW(0,0,0,0);
    check(valid(started)&&valid(phase)&&valid(ready),2);
    InitializeCriticalSection(&cs); EnterCriticalSection(&cs);
    check(TryEnterCriticalSection(&cs),3); LeaveCriticalSection(&cs);
    InitializeSRWLock(&srw); AcquireSRWLockExclusive(&srw); protected_value=1;
    HANDLE t=CreateThread(0,0,worker,(void*)(UPTR)0xBEEF,4,&tid);
    check(valid(t)&&tid!=main_tid&&GetExitCodeThread(t,&code)&&code==259,4);
    check(SuspendThread(t)==1&&ResumeThread(t)==2&&ResumeThread(t)==1,5);
    check(WaitForSingleObject(started,5000)==0,6); Sleep(0); LeaveCriticalSection(&cs);
    check(WaitForSingleObject(phase,5000)==0,7); ReleaseSRWLockExclusive(&srw);
    check(WaitForSingleObject(ready,5000)==0&&QueueUserAPC(apc,t,0xABCD),8);
    check(WaitForSingleObject(t,5000)==0&&GetExitCodeThread(t,&code)&&code==37,9);
    check(TlsGetValue(slot)==(void*)(UPTR)0x123,10);
    check(CloseHandle(t)&&CloseHandle(started)&&CloseHandle(phase)&&CloseHandle(ready),11);
    DeleteCriticalSection(&cs); InitializeConditionVariable(&cv); AcquireSRWLockExclusive(&srw);
    check(!SleepConditionVariableSRW(&cv,&srw,0,0)&&GetLastError()==1460,12);
    ReleaseSRWLockExclusive(&srw); /* Timeout must reacquire. */
    DWORD compare=0; check(WaitOnAddress(&protected_value,&compare,4,0),13);
    compare=protected_value;
    check(!WaitOnAddress(&protected_value,&compare,4,0)&&GetLastError()==1460,14);
    HANDLE e=CreateEventW(0,1,1,L"Local\\RaxServices");
    HANDLE alias=CreateEventW(0,0,0,L"RaxServices");
    check(valid(e)&&valid(alias)&&GetLastError()==183,15);
    HANDLE lower=CreateEventW(0,0,0,L"raxservices");
    check(valid(lower)&&WaitForSingleObject(lower,0)==0x102,16);
    check(!CreateMutexW(0,0,L"RaxServices")&&GetLastError()==6,17);
    HANDLE restricted=OpenEventW(0x00100000,0,L"RaxServices");
    check(valid(restricted)&&!SetEvent(restricted)&&GetLastError()==5,18);
    check(WaitForSingleObject(restricted,0)==0,19);
    check(SetHandleInformation(restricted,2,2)&&GetHandleInformation(restricted,&flags)&&flags==2,20);
    check(!CloseHandle(restricted)&&GetLastError()==6,21);
    check(SetHandleInformation(restricted,2,0)&&CloseHandle(restricted),22);
    HANDLE sem=CreateSemaphoreW(0,0,2,0); LONG previous=-1;
    check(valid(sem)&&ReleaseSemaphore(sem,1,&previous)&&previous==0,23);
    HANDLE pair[2]={e,sem};
    check(WaitForMultipleObjects(2,pair,1,0)==0&&WaitForSingleObject(sem,0)==0x102,24);
    check(ResetEvent(e)&&WaitForSingleObject(alias,0)==0x102,25);
    check(CloseHandle(e)&&CloseHandle(alias)&&CloseHandle(lower)&&CloseHandle(sem),26);
    mutex=CreateMutexW(0,0,0); t=CreateThread(0,0,abandon,mutex,0,&tid);
    check(valid(mutex)&&valid(t)&&WaitForSingleObject(t,5000)==0,27);
    check(WaitForSingleObject(mutex,0)==0x80&&ReleaseMutex(mutex),28);
    check(CloseHandle(t)&&CloseHandle(mutex),29);
    t=CreateThread(0,0,worker,0,4,&tid);
    check(valid(t)&&TerminateThread(t,61)&&WaitForSingleObject(t,5000)==0,30);
    check(GetExitCodeThread(t,&code)&&code==61&&CloseHandle(t)&&TlsFree(slot),31);
}
static void files(void) {
    static const WCHAR path[]=L"C:\\rax-services.dat";
    static const unsigned char bytes[8]={0,1,2,3,0x80,0xFD,0xFE,0xFF};
    unsigned char out[8]; DWORD count=0; LARGE_INTEGER size,offset;
    HANDLE f=CreateFileW(path,0xC0000000,7,0,2,128,0),dup=0;
    check(valid(f)&&GetFileType(f)==1,201);
    check(WriteFile(f,bytes,8,&count,0)&&count==8,202);
    check(GetFileSizeEx(f,&size)&&size.QuadPart==8,203);
    offset.QuadPart=2;
    check(SetFilePointerEx(f,offset,&size,0)&&size.QuadPart==2,204);
    HANDLE p=GetCurrentProcess();
    HANDLE reduced=0;
    check(DuplicateHandle(p,f,p,&reduced,0x80000000,0,0),220);
    check(!WriteFile(reduced,bytes,1,&count,0)&&GetLastError()==5&&CloseHandle(reduced),221);
    check(DuplicateHandle(p,f,p,&dup,0,0,2)&&valid(dup),205);
    check(ReadFile(dup,out,2,&count,0)&&count==2&&out[0]==2&&out[1]==3,206);
    check(ReadFile(f,out,2,&count,0)&&count==2&&out[0]==0x80&&out[1]==0xFD,207);
    check(SetEndOfFile(f)&&GetFileSizeEx(f,&size)&&size.QuadPart==6&&FlushFileBuffers(f),208);
    HANDLE reader=CreateFileW(path,0x80000000,7,0,3,128,0);
    check(valid(reader)&&!WriteFile(reader,bytes,1,&count,0)&&GetLastError()==5,209);
    check(CreateFileW(path,0x80000000,7,0,1,128,0)==(HANDLE)(UPTR)-1&&GetLastError()==80,210);
    check(DeleteFileW(path),211);
    check(CreateFileW(path,0x80000000,7,0,3,128,0)==(HANDLE)(UPTR)-1&&GetLastError()==5,212);
    check(ReadFile(reader,out,8,&count,0)&&count==6,213);
    check(CloseHandle(f)&&CloseHandle(dup)&&CloseHandle(reader),214);
    check(CreateFileW(path,0x80000000,7,0,3,128,0)==(HANDLE)(UPTR)-1&&GetLastError()==2,215);
    HANDLE nul=CreateFileW(L"NUL",0xC0000000,7,0,3,128,0);
    check(valid(nul)&&GetFileType(nul)==2,216);
    check(WriteFile(nul,bytes,8,&count,0)&&count==8,217);
    check(ReadFile(nul,out,8,&count,0)&&count==0&&CloseHandle(nul),218);
    HANDLE exit_file=CreateFileW(L"C:\\rax-services-exit.dat",0xC0010000,7,0,2,0x04000080,0);
    check(valid(exit_file)&&WriteFile(exit_file,bytes,8,&count,0)&&count==8,219);
    /* ExitProcess must close this deliberately unclosed delete-on-close file. */
}
void entry(void) { threads(); files(); ExitProcess(0); }
