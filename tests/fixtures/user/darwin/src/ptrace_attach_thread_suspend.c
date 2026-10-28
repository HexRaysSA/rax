/* Hold a traced thread suspended across PT_CONTINUE, then resume it. */
#include <errno.h>
#include <mach/mach.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile sig_atomic_t tracee;
static void timed_out(int sig) {
    (void)sig;
    if (tracee > 0) kill((pid_t)tracee, SIGKILL);
    _exit(2);
}

int main(int argc, char **argv) {
    if (argc > 2 || (argc == 2 && strcmp(argv[1], "kill") && strcmp(argv[1], "signal") &&
                     strcmp(argv[1], "running") && strcmp(argv[1], "pending"))) return 1;
    setbuf(stdout, NULL);
    int ready[2], gate[2];
    if (pipe(ready) || pipe(gate)) return 1;
    pid_t child = fork();
    if (child < 0) return 1;
    if (child == 0) {
        close(ready[0]); close(gate[1]);
        uint64_t tid = 0;
        if (pthread_threadid_np(NULL, &tid) || write(ready[1], &tid, sizeof tid) != sizeof tid) _exit(90);
        char byte;
        ssize_t n;
        do { n = read(gate[0], &byte, 1); } while (n < 0 && errno == EINTR);
        _exit(n == 1 ? 42 : 91);
    }
    tracee = child;
    signal(SIGALRM, timed_out);
    alarm(60);
    close(ready[1]); close(gate[0]);
    uint64_t tid = 0;
    int status;
    if (read(ready[0], &tid, sizeof tid) != sizeof tid || ptrace(PT_ATTACH, child, 0, 0) ||
        waitpid(child, &status, 0) != child || !WIFSTOPPED(status)) goto fail;
    mach_port_t task = MACH_PORT_NULL;
    if (task_for_pid(mach_task_self(), child, &task)) goto fail;
    thread_act_array_t threads = NULL;
    mach_msg_type_number_t count = 0;
    if (task_threads(task, &threads, &count)) goto fail;
    mach_port_t thread = MACH_PORT_NULL;
    for (mach_msg_type_number_t i = 0; i < count; i++) {
        thread_identifier_info_data_t info = {0};
        mach_msg_type_number_t size = THREAD_IDENTIFIER_INFO_COUNT;
        if (!thread_info(threads[i], THREAD_IDENTIFIER_INFO, (thread_info_t)&info, &size) &&
            info.thread_id == tid) thread = threads[i];
    }
    if (thread == MACH_PORT_NULL) goto fail;
    kern_return_t extra = thread_resume(thread);
    kern_return_t first = thread_suspend(thread), second = thread_suspend(thread);
    if (argc == 2) {
        int result;
        if (!strcmp(argv[1], "kill")) result = ptrace(PT_KILL, child, (caddr_t)1, 0);
        else if (!strcmp(argv[1], "signal")) result = ptrace(PT_CONTINUE, child, (caddr_t)1, SIGKILL);
        else if (!strcmp(argv[1], "pending")) {
            result = kill(child, SIGKILL);
            if (!result) result = ptrace(PT_CONTINUE, child, (caddr_t)1, 0);
        }
        else {
            result = ptrace(PT_CONTINUE, child, (caddr_t)1, 0);
            if (!result) result = kill(child, SIGKILL);
        }
        if (result || waitpid(child, &status, 0) != child) goto fail;
        int prestop = WIFSTOPPED(status) ? WSTOPSIG(status) : 0;
        if (prestop && (ptrace(PT_CONTINUE, child, (caddr_t)1, 0) ||
                        waitpid(child, &status, 0) != child)) goto fail;
        tracee = 0;
        alarm(0);
        int death = WIFSIGNALED(status) ? WTERMSIG(status) : 0;
        if (!strcmp(argv[1], "running")) printf("prestop=%d\n", prestop);
        printf("extra=%d suspend=%d,%d kill=%d signal=%d\n", extra, first, second, result, death);
        return extra != KERN_FAILURE || first || second || death != SIGKILL;
    }
    if (ptrace(PT_CONTINUE, child, (caddr_t)1, 0) || write(gate[1], "x", 1) != 1) goto fail;
    usleep(100000);
    int held_first = waitpid(child, &status, WNOHANG) == 0;
    kern_return_t resume_first = thread_resume(thread);
    usleep(100000);
    int held_second = waitpid(child, &status, WNOHANG) == 0;
    kern_return_t resume_second = thread_resume(thread);
    if (waitpid(child, &status, 0) != child) goto fail;
    tracee = 0;
    alarm(0);
    int exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    printf("extra=%d suspend=%d,%d held=%d,%d resume=%d,%d exit=%d\n", extra, first, second,
           held_first, held_second, resume_first, resume_second, exit_code);
    return extra != KERN_FAILURE || first || second || !held_first || !held_second ||
           resume_first || resume_second || exit_code != 42;
fail:
    kill(child, SIGKILL);
    ptrace(PT_CONTINUE, child, (caddr_t)1, 0);
    waitpid(child, NULL, 0);
    tracee = 0;
    alarm(0);
    return 1;
}
