#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <spawn.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef RAX_THREADED_SPAWN
#include <pthread.h>
#endif

static int spawn_group(const char *path, char *const envp[])
{
    char *const argv[] = {"printf", "spawn:%s\n", "isolated-group", NULL};
    posix_spawnattr_t attributes;
    int error = posix_spawnattr_init(&attributes);
    if (error != 0)
        return error;
    error = posix_spawnattr_setpgroup(&attributes, 0);
    if (error == 0)
        error = posix_spawnattr_setflags(&attributes, POSIX_SPAWN_SETPGROUP);
    pid_t child;
    if (error == 0)
        error = posix_spawn(&child, path, NULL, &attributes, argv, envp);
    posix_spawnattr_destroy(&attributes);
    if (error != 0)
        return error;

    // The process group stays visible even if printf has already exited.
    pid_t group = getpgid(child);
    int status;
    if (waitpid(child, &status, 0) != child || group != child ||
        !WIFEXITED(status) || WEXITSTATUS(status) != 0)
        return ECHILD;
    return 0;
}

static int check_spawn(void)
{
    const char *path = "/usr/bin/printf";
    char *const argv[] = {"printf", "spawn:%s\n", "installed-libc", NULL};
    char *const envp[] = {"LC_ALL=C", NULL};
    pid_t child;
    int status;
    int error = posix_spawn(&child, path, NULL, NULL, argv, envp);
    if (error != 0) {
        fprintf(stderr, "spawn failed: %d\n", error);
        return 1;
    }
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fputs("child did not exit successfully\n", stderr);
        return 2;
    }
    error = spawn_group(path, envp);
    if (error != 0) {
        fprintf(stderr, "spawn with a new process group failed: %d\n", error);
        return 4;
    }
    error = posix_spawn(&child, "/rax-missing-executable", NULL, NULL, argv, envp);
    if (error != ENOENT) {
        fprintf(stderr, "missing executable returned %d\n", error);
        return 3;
    }
    puts("missing:ENOENT");
    return 0;
}

#ifdef RAX_THREADED_SPAWN
static void *wait_during_spawn(void *arg)
{
    pthread_barrier_t *barrier = arg;
    pthread_barrier_wait(barrier);
    pthread_barrier_wait(barrier);
    return NULL;
}
#endif

int main(void)
{
#ifdef RAX_THREADED_SPAWN
    pthread_barrier_t barrier;
    pthread_t worker;
    int error = pthread_barrier_init(&barrier, NULL, 2);
    if (error != 0) {
        fprintf(stderr, "pthread_barrier_init: %d\n", error);
        return 5;
    }
    error = pthread_create(&worker, NULL, wait_during_spawn, &barrier);
    if (error != 0) {
        fprintf(stderr, "pthread_create: %d\n", error);
        pthread_barrier_destroy(&barrier);
        return 6;
    }

    pthread_barrier_wait(&barrier);
    int result = check_spawn();
    pthread_barrier_wait(&barrier);
    error = pthread_join(worker, NULL);
    pthread_barrier_destroy(&barrier);
    if (error != 0) {
        fprintf(stderr, "pthread_join: %d\n", error);
        return 7;
    }
    return result;
#else
    return check_spawn();
#endif
}
