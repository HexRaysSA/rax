#define _GNU_SOURCE
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>
#include <stdint.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { NT_PRSTATUS_LOCAL=1, NT_BREAK=0x402, NT_WATCH=0x403 };
struct debug_state {
    uint32_t info,pad;
    struct { uint64_t address; uint32_t control,pad; } slots[16];
};
struct user_regs { uint64_t x[31],sp,pc,pstate; };
extern void probe_point(void),probe_access(void),probe_write(void),probe_read(void);
extern uint64_t probe_data;
__asm__(".text\n.balign 4\n.globl probe_point\nprobe_point:\n add x0,x0,#1\n ret\n"
        ".globl probe_access\nprobe_access:\n adrp x1,probe_data\n add x1,x1,:lo12:probe_data\n mov x0,#41\n"
        ".globl probe_write\nprobe_write:\n str x0,[x1]\n"
        ".globl probe_read\nprobe_read:\n ldr x0,[x1]\n ret\n"
        ".bss\n.balign 8\n.globl probe_data\nprobe_data:\n .skip 8\n.text\n");

static int regset(pid_t pid,int write,unsigned note,void *buffer,size_t *size) {
    struct iovec iov={buffer,*size};errno=0;
    long ret=ptrace(write?PTRACE_SETREGSET:PTRACE_GETREGSET,pid,note,&iov);
    int error=errno;*size=iov.iov_len;return ret<0?error:0;
}

static void dump(pid_t pid,unsigned note,const char *phase,int result,size_t copied) {
    struct debug_state s={0};size_t size=sizeof(s);int error=regset(pid,0,note,&s,&size);
    printf("{\"phase\":\"%s\",\"note\":%u,\"errno\":%d,\"copied\":%zu,\"get_errno\":%d,\"get_size\":%zu,\"info\":%u,\"slots\":[",phase,note,result,copied,error,size,s.info);
    for(int i=0;i<16;i++)printf("%s{\"address\":\"%llx\",\"control\":\"%x\"}",i?",":"",(unsigned long long)s.slots[i].address,s.slots[i].control);
    puts("]}");
}

static pid_t stopped_child(void) {
    pid_t pid=fork();if(pid<0)exit(2);
    if(!pid) {
        if(ptrace(PTRACE_TRACEME,0,0,0))_exit(2);
        raise(SIGSTOP);probe_point();probe_access();_exit(0);
    }
    int status;if(waitpid(pid,&status,0)!=pid||!WIFSTOPPED(status))exit(3);
    if(ptrace(PTRACE_SETOPTIONS,pid,0,PTRACE_O_EXITKILL))exit(4);
    return pid;
}

static int finish(pid_t pid,unsigned note,int armed) {
    int traps=0;
    for(int i=0;i<5;i++) {
        if(ptrace(PTRACE_CONT,pid,0,0))return 10;
        int status;if(waitpid(pid,&status,0)!=pid)return 11;
        if(WIFEXITED(status)) {
            printf("{\"phase\":\"exit\",\"code\":%d,\"traps\":%d}\n",WEXITSTATUS(status),traps);
            return WEXITSTATUS(status);
        }
        if(!WIFSTOPPED(status)||WSTOPSIG(status)!=SIGTRAP)return 12;
        struct user_regs regs={0};siginfo_t info={0};size_t size=sizeof(regs);
        if(regset(pid,0,NT_PRSTATUS_LOCAL,&regs,&size)||ptrace(PTRACE_GETSIGINFO,pid,0,&info))return 13;
        errno=0;unsigned long data=ptrace(PTRACE_PEEKDATA,pid,(void*)&probe_data,0);if(errno)return 14;
        printf("{\"phase\":\"trap\",\"count\":%d,\"code\":%d,\"pc\":\"%llx\",\"addr\":\"%llx\",\"pstate\":\"%llx\",\"data\":\"%lx\"}\n",++traps,info.si_code,(unsigned long long)regs.pc,(unsigned long long)(uintptr_t)info.si_addr,(unsigned long long)regs.pstate,data);
        // Observe a second CONT without changing the comparator, then disarm.
        if(traps==2||!armed) {
            struct debug_state s={0};size=sizeof(s);if(regset(pid,0,note,&s,&size))return 15;
            s.slots[0].control=0;size=24;if(regset(pid,1,note,&s,&size))return 16;
            armed=0;
        }
    }
    return 17;
}

int main(void) {
    setvbuf(stdout,NULL,_IONBF,0);alarm(30);
    printf("{\"probe_point\":\"%llx\",\"probe_write\":\"%llx\",\"probe_read\":\"%llx\",\"probe_data\":\"%llx\"}\n",(unsigned long long)(uintptr_t)probe_point,(unsigned long long)(uintptr_t)probe_write,(unsigned long long)(uintptr_t)probe_read,(unsigned long long)(uintptr_t)&probe_data);
    for(int c=0;c<10;c++) {
        pid_t pid=stopped_child();unsigned note=c>=8?NT_WATCH:NT_BREAK;
        printf("{\"case\":%d,\"note\":%u}\n",c,note);dump(pid,note,"initial",0,0);
        struct debug_state s={0};s.info=~0U;s.pad=~0U;s.slots[0].address=(uintptr_t)probe_point;s.slots[0].control=0x1e5;
        size_t size=24;int armed=1;
        switch(c) {
        case 0:s.slots[0].control=0;armed=0;break;
        case 1:break;
        case 2:s.slots[0].control=0xffffe1e1;break;
        case 3:s.slots[0].control=0x65;break;
        case 4:s.slots[0].control=0xa5;armed=0;break;
        case 5:size=16;armed=0;break;
        case 6:size=12;armed=0;break;
        case 7:memset(&s,0,sizeof(s));size=sizeof(s);armed=0;break;
        case 8:s.slots[0].address=(uintptr_t)&probe_data;s.slots[0].control=0xfffffffeU;armed=0;break;
        case 9:s.slots[0].address=(uintptr_t)&probe_data;s.slots[0].control=0x1ff5;break;
        }
        int error=regset(pid,1,note,&s,&size);dump(pid,note,"after-set",error,size);
        int ret=finish(pid,note,armed&&!error);if(ret)return ret;
    }
    return 0;
}
