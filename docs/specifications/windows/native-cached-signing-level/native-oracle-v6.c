/* Read-only query publication into caller-owned buffers and aliases. */
#define entry original_entry
#include "native-oracle-v1.c"
#undef entry

static UCHAR saved_pages[96];
static unsigned optional_mask;
static unsigned capture_capacity;
static const unsigned aliases[][5] = {
    {0,16,32,112,128}, {0,0,32,112,128}, {112,16,32,112,128},
    {0,16,32,112,112}, {32,16,32,112,128}, {0,32,32,112,128},
    {0,16,32,32,128}, {0,16,32,112,32}, {112,112,32,112,112}
};

static void emit(const char *role, const char *shape, unsigned ordinal, unsigned slot,
                 unsigned position, DWORD protection, LONG result, DWORD remaining,
                 UCHAR *pages) {
    unsigned i;
    begin("publication-v6",role);
    text(",\"capacity\":\"");hex(capture_capacity,8);put('"');
    text(",\"null_mask\":\"");hex(optional_mask,2);put('"');
    text(",\"shape\":");quoted(shape);
    text(",\"ordinal\":\"");hex(ordinal,4);put('"');
    text(",\"slot\":\"");hex(slot,2);put('"');
    text(",\"position\":\"");hex(position,4);put('"');
    text(",\"protection\":\"");hex(protection,8);put('"');
    text(",\"remaining_protection\":\"");hex(remaining,8);put('"');
    text(",\"result\":\"");hex((ULONG)result,8);put('"');
    text(",\"arena\":\"");for(i=0;i<sizeof(arena.bytes);++i)hex(arena.bytes[i],2);put('"');
    text(",\"pages_before\":\"");for(i=0;i<96;++i)hex(saved_pages[i],2);put('"');
    text(",\"pages_after\":\"");for(i=0;i<96;++i)hex(pages[4096-32+i],2);put('"');
    finish();
}

static void publication(const char *role,HANDLE file,unsigned capacity) {
    optional_mask=0;capture_capacity=capacity;
    unsigned mask=0;
    static const unsigned positions[]={4096,4095,4094,4093,4092,4091,4090,4089,4088,4087,4086,4085,4084,4083,4082,4081,4080,4079,4078,4077,4076,4075,4074,4073,4072,4071,4070,4069,4068,4067,4066,4065,4064,4063,4062,4061,4060,4059,4058,4057,4056,4055,4054,4053,4052,4051,4050,4049,4048,4047,4046,4045,4044,4043,4042,4041,4040,4039,4038,4037,4036,4035,4034,4033,4032};
    static const DWORD protections[]={PAGE_NOACCESS,PAGE_READONLY,PAGE_READWRITE|PAGE_GUARD,PAGE_READONLY|PAGE_GUARD};
    UCHAR *pages=(UCHAR *)VirtualAlloc(0,8192,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
    void *pointers[5];
    unsigned i,j,k,n,ordinal=0;
    DWORD previous;
    if(!pages)ExitProcess(20);
    for(i=2;i<3;++i)for(j=0;j<65;++j)for(k=0;k<4;++k) {
        if(mask & (1u<<i))continue;
        MEMORY_BASIC_INFORMATION information;
        LONG result;
        initialize(capacity);
        pointers[0]=&arena.bytes[0];pointers[1]=&arena.bytes[16];pointers[2]=&arena.bytes[32];
        pointers[3]=&arena.bytes[112];pointers[4]=&arena.bytes[128];
        for(n=0;n<8192;++n)pages[n]=0xa5;
        pointers[i]=pages+positions[j];
        if(i==3)for(n=0;n<4;++n)((UCHAR *)pointers[3])[n]=(UCHAR)(capacity>>(n*8));
        for(n=0;n<96;++n)saved_pages[n]=pages[4096-32+n];
        if(!VirtualProtect(pages+4096,4096,protections[k],&previous))ExitProcess(21);
        for(n=0;n<5;++n)if(mask & (1u<<n))pointers[n]=0;
        result=query(file,(ULONG *)pointers[0],(UCHAR *)pointers[1],
                     (UCHAR *)pointers[2],(ULONG *)pointers[3],(ULONG *)pointers[4]);
        if(!VirtualQuery(pages+4096,&information,sizeof(information)))ExitProcess(22);
        if(!VirtualProtect(pages+4096,4096,PAGE_READWRITE,&previous))ExitProcess(23);
        emit(role,"page",ordinal++,i,positions[j],protections[k],result,information.Protect,pages);
    }
    if(!VirtualFree(pages,0,MEM_RELEASE))ExitProcess(24);
}

void entry(void) {
    WCHAR directory[512],path[1024];
    HANDLE signed_file,limited,unsigned_file,event;
    query=(QuerySigning)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtGetCachedSigningLevel");
    if(!query || !GetSystemDirectoryW(directory,512))ExitProcess(10);
    path_join(path,directory,L"ntdll.dll");
    signed_file=CreateFileW(path,GENERIC_READ,7,0,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0);
    limited=CreateFileW(path,FILE_READ_ATTRIBUTES,7,0,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0);
    if(!GetModuleFileNameW(0,path,1024))ExitProcess(11);
    unsigned_file=CreateFileW(path,GENERIC_READ,7,0,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0);
    event=CreateEventW(0,FALSE,FALSE,0);
    if(signed_file==INVALID_HANDLE_VALUE || limited==INVALID_HANDLE_VALUE || unsigned_file==INVALID_HANDLE_VALUE || !event)ExitProcess(12);
    const unsigned capacities[]={64};
    for(unsigned i=0;i<1;++i) {
        publication("signed-file",signed_file,capacities[i]);
    }
    if(!CloseHandle(signed_file)||!CloseHandle(limited)||!CloseHandle(unsigned_file)||!CloseHandle(event))ExitProcess(13);
    ExitProcess(0);
}
