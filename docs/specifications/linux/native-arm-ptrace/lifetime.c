#define main unused_regset_control_main
#include "control.c"
#undef main

static int empty_bank(pid_t pid) {
    struct debug_state s={0};size_t size=sizeof(s);
    if(regset(pid,0,NT_BREAK,&s,&size))return 1;
    for(int n=0;n<16;n++)if(s.slots[n].address||s.slots[n].control)return 2;
    return 0;
}

int main(int argc,char **argv) {
    if(argc>1)_exit(0);
    setvbuf(stdout,NULL,_IONBF,0);alarm(30);
    for(int mode=0;mode<2;mode++) {
        pid_t child=fork();if(child<0)return 2;
        if(!child) {
            if(ptrace(PTRACE_TRACEME,0,0,0))_exit(2);
            raise(SIGSTOP);
            if(mode) {
                char *args[]={argv[0],"post-exec",NULL};execv(argv[0],args);_exit(3);
            }
            if(fork()<0)_exit(4);
            _exit(0);
        }
        int status;if(waitpid(child,&status,0)!=child||!WIFSTOPPED(status))return 3;
        unsigned long options=PTRACE_O_EXITKILL|(mode?PTRACE_O_TRACEEXEC:PTRACE_O_TRACEFORK);
        if(ptrace(PTRACE_SETOPTIONS,child,0,options))return 4;
        struct debug_state s={0};s.slots[0].address=(uintptr_t)probe_point;s.slots[0].control=0x1e5;size_t size=24;
        if(regset(child,1,NT_BREAK,&s,&size))return 5;
        if(ptrace(PTRACE_CONT,child,0,0)||waitpid(child,&status,0)!=child||!WIFSTOPPED(status))return 6;
        unsigned long event=(unsigned)status>>16;
        if(event!=(mode?PTRACE_EVENT_EXEC:PTRACE_EVENT_FORK))return 7;
        if(mode) {
            int empty=empty_bank(child);printf("{\"case\":\"exec\",\"empty_bank\":%d}\n",empty);if(empty)return 8;
            if(ptrace(PTRACE_CONT,child,0,0)||waitpid(child,&status,0)!=child||!WIFEXITED(status)||WEXITSTATUS(status))return 9;
        } else {
            unsigned long grandchild;if(ptrace(PTRACE_GETEVENTMSG,child,0,&grandchild))return 10;
            if(waitpid(grandchild,&status,0)!=(pid_t)grandchild||!WIFSTOPPED(status))return 11;
            int empty=empty_bank(grandchild);printf("{\"case\":\"fork\",\"empty_bank\":%d}\n",empty);if(empty)return 12;
            if(ptrace(PTRACE_CONT,child,0,0)||ptrace(PTRACE_CONT,grandchild,0,0))return 13;
            for(int n=0;n<2;n++)if(waitpid(-1,&status,0)<0||!WIFEXITED(status)||WEXITSTATUS(status))return 14;
        }
        printf("{\"case\":%d,\"completed\":true}\n",mode);
    }
    return 0;
}
