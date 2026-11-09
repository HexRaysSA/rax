/* Read-only query publication into caller-owned buffers and aliases. */
#define entry original_entry
#include "native-oracle-v1.c"
#undef entry

static UCHAR saved_pages[96];
static const unsigned aliases[][5] = {
    {0,16,32,112,128}, {0,0,32,112,128}, {112,16,32,112,128},
    {0,16,32,112,112}, {32,16,32,112,128}, {0,32,32,112,128},
    {0,16,32,32,128}, {0,16,32,112,32}, {112,112,32,112,112}
};

static void emit(const char *role, const char *shape, unsigned ordinal, unsigned slot,
                 unsigned position, DWORD protection, LONG result, DWORD remaining,
                 UCHAR *pages) {
    unsigned i;
    begin("publication-v2",role);
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

static void publication(const char *role,HANDLE file) {
    static const unsigned positions[]={4096,4095,4093,4092};
    static const DWORD protections[]={PAGE_NOACCESS,PAGE_READONLY,PAGE_READWRITE|PAGE_GUARD};
    UCHAR *pages=(UCHAR *)VirtualAlloc(0,8192,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
    void *pointers[5];
    unsigned i,j,k,n,ordinal=0;
    DWORD previous;
    if(!pages)ExitProcess(20);
    for(i=0;i<sizeof(aliases)/sizeof(aliases[0]);++i) {
        initialize(64);
        for(j=0;j<5;++j)pointers[j]=&arena.bytes[aliases[i][j]];
        for(j=0;j<4;++j)((UCHAR *)pointers[3])[j]=(UCHAR)(64u>>(j*8));
        for(j=0;j<8192;++j)pages[j]=0xa5;
        for(j=0;j<96;++j)saved_pages[j]=pages[4096-32+j];
        LONG result=query(file,(ULONG *)pointers[0],(UCHAR *)pointers[1],
                          (UCHAR *)pointers[2],(ULONG *)pointers[3],(ULONG *)pointers[4]);
        emit(role,"alias",i,0,0,PAGE_READWRITE,result,PAGE_READWRITE,pages);
    }
    for(i=0;i<5;++i)for(j=0;j<4;++j)for(k=0;k<3;++k) {
        MEMORY_BASIC_INFORMATION information;
        LONG result;
        initialize(64);
        pointers[0]=&arena.bytes[0];pointers[1]=&arena.bytes[16];pointers[2]=&arena.bytes[32];
        pointers[3]=&arena.bytes[112];pointers[4]=&arena.bytes[128];
        for(n=0;n<8192;++n)pages[n]=0xa5;
        pointers[i]=pages+positions[j];
        if(i==3)for(n=0;n<4;++n)((UCHAR *)pointers[3])[n]=(UCHAR)(64u>>(n*8));
        for(n=0;n<96;++n)saved_pages[n]=pages[4096-32+n];
        if(!VirtualProtect(pages+4096,4096,protections[k],&previous))ExitProcess(21);
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
    publication("signed-file",signed_file);
    publication("unsigned-file",unsigned_file);
    publication("limited-file",limited);
    publication("null-handle",0);
    publication("event-handle",event);
    if(!CloseHandle(signed_file)||!CloseHandle(limited)||!CloseHandle(unsigned_file)||!CloseHandle(event))ExitProcess(13);
    ExitProcess(0);
}
