/* XNU kern_event.c:filt_procevent emits guest exit before ptrace reaping. */
#include <errno.h>
#include <mach/mach.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/event.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile sig_atomic_t done;
static void finish(int signo) { (void)signo; done = 1; }

int main(int argc, char **argv) {
    alarm(20);
    if (argc == 2 && strcmp(argv[1], "target") == 0) {
        signal(SIGUSR1, finish);
        puts("ready");
        fflush(stdout);
        while (!done) pause();
        return 42;
    }
    if (argc != 3) return 80;
    pid_t pid = (pid_t)strtol(argv[2], NULL, 10);
    if (ptrace(PT_ATTACH, pid, 0, 0)) return 1;
    int status = 0;
    if (waitpid(pid, &status, WUNTRACED) != pid || !WIFSTOPPED(status)) return 2;
    task_t task = MACH_PORT_NULL;
    if (task_for_pid(mach_task_self(), pid, &task)) return 11;
    task_suspension_token_t token = MACH_PORT_NULL;
    if (task_suspend2(task, &token) || task_resume(task)) return 13;
    int retain = strcmp(argv[1], "event-reap") == 0;
    int queue = kqueue();
    if (queue < 0) return 3;
    struct kevent change, event;
    unsigned int interest = NOTE_EXIT | NOTE_EXITSTATUS;
    if (retain) interest |= NOTE_REAP;
    EV_SET(&change, pid, EVFILT_PROC, EV_ADD, interest, 0, (void *)0x1234);
    if (kevent(queue, &change, 1, NULL, 0, NULL)) return 4;
    if (ptrace(PT_CONTINUE, pid, (caddr_t)1, SIGUSR1)) return 5;
    struct timespec timeout = {5, 0};
    int count;
    do { count = kevent(queue, NULL, 0, &event, 1, &timeout); } while (count < 0 && errno == EINTR);
    int identity = count == 1 && event.ident == (uintptr_t)pid && event.filter == EVFILT_PROC && event.udata == (void *)0x1234;
    int flags = count == 1 && (event.fflags & (NOTE_EXIT | NOTE_EXITSTATUS)) == (NOTE_EXIT | NOTE_EXITSTATUS);
    int terminal = count == 1 && (event.flags & (EV_EOF | EV_ONESHOT)) == (retain ? 0 : (EV_EOF | EV_ONESHOT));
    int data = count == 1 && event.data == (42 << 8);
    printf("event=%d identity=%d flags=%d terminal=%d status=%d\n", count, identity, flags, terminal, data);
    fflush(stdout);
    if (count != 1 || !identity || !flags || !terminal || !data) return 6;
    mach_port_type_t type = 0;
    kern_return_t result = KERN_SUCCESS;
    int dead = 0;
    for (int i = 0; i < 500 && !dead; ++i) {
        result = mach_port_type(mach_task_self(), task, &type);
        dead = result == KERN_SUCCESS && type == MACH_PORT_TYPE_DEAD_NAME;
        if (!dead) usleep(10000);
    }
    printf("task-dead=%d\n", dead);
    if (!dead) return 12;
    int token_dead = 0;
    for (int i = 0; i < 500 && !token_dead; ++i) {
        type = 0;
        token_dead = mach_port_type(mach_task_self(), token, &type) == KERN_SUCCESS
            && type == MACH_PORT_TYPE_DEAD_NAME;
        if (!token_dead) usleep(10000);
    }
    printf("token-dead=%d\n", token_dead);
    if (!token_dead) return 14;
    task_t again = 123;
    result = task_for_pid(mach_task_self(), pid, &again);
    printf("reacquire=%d null=%d\n", result, again == MACH_PORT_NULL);
    if (result != KERN_FAILURE || again != MACH_PORT_NULL) return 15;
    mach_port_deallocate(mach_task_self(), token);
    mach_port_deallocate(mach_task_self(), task);
    timeout = (struct timespec){0, 0};
    count = kevent(queue, NULL, 0, &event, 1, &timeout);
    printf("empty=%d\n", count == 0);
    if (count != 0) return 7;
    int late = kqueue();
    if (late < 0) return 9;
    EV_SET(&change, pid, EVFILT_PROC, EV_ADD, NOTE_EXIT, 0, NULL);
    errno = 0;
    count = kevent(late, &change, 1, NULL, 0, NULL);
    printf("late=%d errno=%d\n", count, errno);
    if (count != -1 || errno != ESRCH) return 10;
    close(late);
    close(queue);
    if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status) || WEXITSTATUS(status) != 42) return 8;
    puts("exited=1 status=42");
    return 0;
}
