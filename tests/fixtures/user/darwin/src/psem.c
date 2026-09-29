// POSIX named semaphores: sem_open's name limit, flags, value, and
// errors; the descriptor a semaphore is (its number, not close-on-exec,
// shared by name between opens and with a forked child); counting with
// sem_post and sem_trywait; sem_wait woken by another thread and by
// another process, interrupted by a signal (with and without SA_RESTART),
// and cancelled; the refusals of descriptors of another kind; sem_unlink.
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

static char name[32], other[32];

static int err(int r) { return r == 0 ? 0 : errno; }

static sem_t *open_err(const char *n, int oflag, unsigned value, int *e) {
    errno = 0;
    sem_t *s = sem_open(n, oflag, 0600, value);
    *e = s == SEM_FAILED ? errno : 0;
    return s;
}

static void *poster(void *arg) {
    usleep(20000);
    sem_post((sem_t *)arg);
    return NULL;
}

static void *waiter(void *arg) {
    sem_wait((sem_t *)arg);
    return (void *)1;
}

static void on_alarm(int sig) { (void)sig; }

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    snprintf(name, sizeof name, "/rax-psem-%d", getpid());
    snprintf(other, sizeof other, "/rax-psem-o-%d", getpid());
    int e;

    // Names: 30 characters fit (31 with the NUL), 31 do not.
    char n30[31], n31[32];
    memset(n30, 'a', 30), n30[30] = 0, n30[0] = '/';
    memset(n31, 'b', 31), n31[31] = 0, n31[0] = '/';
    snprintf(n30 + 18, 13, "%012d", getpid());
    sem_t *s = open_err(n30, O_CREAT, 0, &e);
    printf("30-character name: %d\n", e);
    if (!e) sem_close(s), sem_unlink(n30);
    open_err(n31, O_CREAT, 0, &e);
    printf("31-character name: %d\n", e);
    errno = 0;
    printf("unlink 31-character name: %d\n", err(sem_unlink(n31)));

    // Flags and value.
    open_err(name, 0, 0, &e);
    printf("no such semaphore: %d\n", e);
    open_err(name, O_CREAT, (unsigned)SEM_VALUE_MAX + 1, &e);
    printf("value too large: %d\n", e);
    int lowest = dup(0);
    close(lowest);
    sem_t *a = open_err(name, O_CREAT | O_EXCL, 1, &e);
    printf("created: %d, descriptor is the lowest free %d\n", e, (int)(intptr_t)a == lowest);
    printf("close-on-exec: %d\n", fcntl((int)(intptr_t)a, F_GETFD));
    open_err(name, O_CREAT | O_EXCL, 1, &e);
    printf("exclusive again: %d\n", e);
    sem_t *b = open_err(name, O_CREAT, 5, &e);
    printf("opened again: %d, another descriptor %d\n", e, a != b);

    // Counting, through either descriptor.
    printf("trywait: %d\n", err(sem_trywait(a)));
    printf("trywait empty: %d\n", err(sem_trywait(b)));
    sem_post(b), sem_post(b);
    printf("after two posts: %d %d %d\n", err(sem_trywait(a)), err(sem_trywait(a)), err(sem_trywait(b)));
    int v = 0;
    printf("getvalue: %d\n", err(sem_getvalue(a, &v)));

    // Waits: woken by another thread.
    pthread_t t;
    pthread_create(&t, NULL, poster, a);
    printf("wait for a thread: %d\n", err(sem_wait(a)));
    pthread_join(t, NULL);

    // Woken by another process.
    pid_t pid = fork();
    if (pid == 0) {
        usleep(20000);
        sem_t *c = sem_open(name, 0);
        _exit(c == SEM_FAILED ? 1 : sem_post(c) != 0);
    }
    printf("wait for a child: %d\n", err(sem_wait(b)));
    int st;
    waitpid(pid, &st, 0);
    printf("child: %d\n", WEXITSTATUS(st));

    // Interrupted by a signal, with and without SA_RESTART.
    for (int restart = 0; restart < 2; restart++) {
        struct sigaction sa = {0};
        sa.sa_handler = on_alarm;
        sa.sa_flags = restart ? SA_RESTART : 0;
        sigaction(SIGALRM, &sa, NULL);
        struct itimerval it = {{0, 0}, {0, 20000}};
        setitimer(ITIMER_REAL, &it, NULL);
        printf("interrupted (SA_RESTART %d): %d\n", restart, err(sem_wait(a)));
    }

    // Cancelled while it waits.
    pthread_create(&t, NULL, waiter, a);
    usleep(20000);
    pthread_cancel(t);
    void *ret = NULL;
    pthread_join(t, &ret);
    printf("cancelled: %d\n", ret == PTHREAD_CANCELED);

    // Other descriptors are not semaphores; sem_close closes.
    int fds[2];
    pipe(fds);
    printf("pipe: wait %d trywait %d post %d close %d\n", err(sem_wait((sem_t *)(intptr_t)fds[0])),
           err(sem_trywait((sem_t *)(intptr_t)fds[0])), err(sem_post((sem_t *)(intptr_t)fds[0])),
           err(sem_close((sem_t *)(intptr_t)fds[0])));
    printf("not open: %d\n", err(sem_post((sem_t *)(intptr_t)999)));
    printf("close: %d, again %d\n", err(sem_close(b)), err(sem_close(b)));
    printf("closed descriptor: %d\n", fcntl((int)(intptr_t)b, F_GETFD) < 0 ? errno : 0);

    // Unlinked: the name is gone, open descriptors still work.
    printf("unlink: %d, again %d\n", err(sem_unlink(name)), err(sem_unlink(name)));
    open_err(name, 0, 0, &e);
    printf("open unlinked: %d\n", e);
    sem_post(a);
    printf("unlinked still counts: %d\n", err(sem_trywait(a)));
    sem_t *o = open_err(other, O_CREAT, 0, &e);
    printf("another name is another semaphore: %d %d\n", e, err(sem_trywait(o)));
    sem_close(o), sem_unlink(other), sem_close(a);
    return 0;
}
