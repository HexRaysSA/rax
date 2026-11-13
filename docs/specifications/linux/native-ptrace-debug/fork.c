#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <signal.h>
#include <stddef.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

static unsigned long peek(pid_t pid, int n) {
    errno=0;
    unsigned long v=ptrace(PTRACE_PEEKUSER,pid,offsetof(struct user,u_debugreg[n]),0);
    if(errno) { perror("peek"); exit(2); }
    return v;
}
int main(void) {
    setvbuf(stdout,NULL,_IONBF,0);alarm(15);
    pid_t child=fork();if(child<0)return 2;
    if(!child) {
        if(ptrace(PTRACE_TRACEME,0,0,0))_exit(2);
        raise(SIGSTOP);
        pid_t grandchild=fork();if(grandchild<0)_exit(3);
        _exit(0);
    }
    int status;if(waitpid(child,&status,0)!=child||!WIFSTOPPED(status))return 3;
    if(ptrace(PTRACE_SETOPTIONS,child,0,PTRACE_O_EXITKILL|PTRACE_O_TRACEFORK))return 4;
    if(ptrace(PTRACE_POKEUSER,child,offsetof(struct user,u_debugreg[0]),0x401000)||
       ptrace(PTRACE_POKEUSER,child,offsetof(struct user,u_debugreg[7]),1)||
       ptrace(PTRACE_POKEUSER,child,offsetof(struct user,u_debugreg[6]),0x4001))return 5;
    if(ptrace(PTRACE_CONT,child,0,0)||waitpid(child,&status,0)!=child||status>>16!=PTRACE_EVENT_FORK)return 6;
    unsigned long grandchild;if(ptrace(PTRACE_GETEVENTMSG,child,0,&grandchild))return 7;
    if(waitpid(grandchild,&status,0)!=(pid_t)grandchild||!WIFSTOPPED(status))return 8;
    printf("{\"parent_dr0\":\"%lx\",\"parent_dr6\":\"%lx\",\"parent_dr7\":\"%lx\",\"child_dr0\":\"%lx\",\"child_dr6\":\"%lx\",\"child_dr7\":\"%lx\"}\n",peek(child,0),peek(child,6),peek(child,7),peek(grandchild,0),peek(grandchild,6),peek(grandchild,7));
    if(ptrace(PTRACE_CONT,child,0,0)||ptrace(PTRACE_CONT,grandchild,0,0))return 9;
    for(int n=0;n<2;n++){pid_t p=waitpid(-1,&status,0);if(p<0||!WIFEXITED(status)||WEXITSTATUS(status))return 10;}
    return 0;
}
