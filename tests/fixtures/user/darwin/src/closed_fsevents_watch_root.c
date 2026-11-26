#include <CoreServices/CoreServices.h>
#include <assert.h>
#include <dispatch/dispatch.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/event.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

enum mutation {
    RENAME_ROOT,
    RENAME_ANCESTOR,
    REMOVE_ROOT,
};

struct watch {
    const char *path;
    dispatch_semaphore_t changed;
};

static void on_events(ConstFSEventStreamRef stream, void *opaque, size_t count,
                      void *paths, const FSEventStreamEventFlags flags[],
                      const FSEventStreamEventId ids[]) {
    (void)stream;
    const struct watch *state = opaque;
    char **names = paths;
    for (size_t i = 0; i < count; ++i) {
        if (flags[i] == kFSEventStreamEventFlagRootChanged && ids[i] == 0 &&
            !strcmp(names[i], state->path)) {
            dispatch_semaphore_signal(state->changed);
        }
    }
}

static void finish_callbacks(void *unused) {
    (void)unused;
}

static void make_path(char path[PATH_MAX], const char *base, const char *suffix) {
    int length = snprintf(path, PATH_MAX, "%s%s", base, suffix);
    assert(length > 0 && length < PATH_MAX);
}

static void rename_in_child(const char *from, const char *to) {
    pid_t pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        _exit(rename(from, to) == 0 ? 0 : 1);
    }
    int status;
    assert(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static void check_root_change(const char *prefix, enum mutation change) {
    char temporary[PATH_MAX], parent[PATH_MAX], path[PATH_MAX];
    make_path(temporary, prefix, ".XXXXXX");
    assert(mkdtemp(temporary) && realpath(temporary, parent));
    make_path(path, parent, "/watched");
    assert(mkdir(path, 0700) == 0);

    struct watch state = {path, dispatch_semaphore_create(0)};
    assert(state.changed);
    FSEventStreamContext context = {.info = &state};
    CFStringRef name = CFStringCreateWithCString(NULL, path, kCFStringEncodingUTF8);
    assert(name);
    const void *value = name;
    CFArrayRef paths = CFArrayCreate(NULL, &value, 1, &kCFTypeArrayCallBacks);
    assert(paths);
    FSEventStreamRef stream = FSEventStreamCreate(
        NULL, on_events, &context, paths, kFSEventStreamEventIdSinceNow, 0.05,
        kFSEventStreamCreateFlagWatchRoot | kFSEventStreamCreateFlagNoDefer);
    CFRelease(paths);
    CFRelease(name);
    assert(stream);
    dispatch_queue_t queue = dispatch_queue_create("rax.fsevents.watch-root", DISPATCH_QUEUE_SERIAL);
    assert(queue);
    FSEventStreamSetDispatchQueue(stream, queue);
    assert(FSEventStreamStart(stream));

    char moved[PATH_MAX];
    if (change == REMOVE_ROOT) {
        assert(rmdir(path) == 0);
    } else if (change == RENAME_ANCESTOR) {
        make_path(moved, parent, ".moved");
        rename_in_child(parent, moved);
        make_path(parent, moved, "");
        make_path(moved, parent, "/watched");
    } else {
        make_path(moved, parent, "/moved");
        assert(rename(path, moved) == 0);
    }
    assert(dispatch_semaphore_wait(state.changed,
                                   dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC)) == 0);

    FSEventStreamStop(stream);
    FSEventStreamInvalidate(stream);
    FSEventStreamRelease(stream);
    dispatch_sync_f(queue, NULL, finish_callbacks);
    dispatch_release(queue);
    dispatch_release(state.changed);
    if (change != REMOVE_ROOT) {
        assert(rmdir(moved) == 0);
    }
    assert(rmdir(parent) == 0);
}

static void check_replaced_vnode(const char *prefix, unsigned int flags) {
    char parent[PATH_MAX], source[PATH_MAX], target[PATH_MAX];
    make_path(parent, prefix, ".XXXXXX");
    assert(mkdtemp(parent));
    make_path(source, parent, "/source");
    make_path(target, parent, "/target");
    assert(mkdir(source, 0700) == 0 && mkdir(target, 0700) == 0);
    int source_fd = open(source, O_EVTONLY);
    int target_fd = open(target, O_EVTONLY);
    int queue = kqueue();
    assert(source_fd >= 0 && target_fd >= 0 && queue >= 0);

    struct kevent changes[2], events[2];
    struct timespec poll = {0};
    const unsigned int mask = NOTE_RENAME | NOTE_DELETE;
    EV_SET(&changes[0], source_fd, EVFILT_VNODE, EV_ADD | EV_CLEAR, mask, 0, NULL);
    EV_SET(&changes[1], target_fd, EVFILT_VNODE, EV_ADD | EV_CLEAR, mask, 0, NULL);
    assert(kevent(queue, changes, 2, NULL, 0, NULL) == 0);
    assert(renameatx_np(AT_FDCWD, source, AT_FDCWD, target, flags) == 0);
    assert(kevent(queue, NULL, 0, events, 2, &poll) == 2);
    unsigned int from = 0, to = 0;
    for (int i = 0; i < 2; ++i) {
        assert(events[i].filter == EVFILT_VNODE);
        if (events[i].ident == (uintptr_t)source_fd) {
            from = events[i].fflags;
        } else {
            assert(events[i].ident == (uintptr_t)target_fd);
            to = events[i].fflags;
        }
    }
    assert(from == NOTE_RENAME && to == NOTE_DELETE);
    assert(kevent(queue, NULL, 0, events, 2, &poll) == 0);

    assert(close(queue) == 0 && close(source_fd) == 0 && close(target_fd) == 0);
    if (flags == RENAME_SWAP) {
        assert(rmdir(source) == 0);
    }
    assert(rmdir(target) == 0 && rmdir(parent) == 0);
}

int main(int argc, char **argv) {
    assert(argc == 2);
    check_root_change(argv[1], RENAME_ROOT);
    check_root_change(argv[1], RENAME_ANCESTOR);
    check_root_change(argv[1], REMOVE_ROOT);
    check_replaced_vnode(argv[1], 0);
    check_replaced_vnode(argv[1], RENAME_SWAP);
    puts("FSEvents watch root reported directory renames and removal");
    return 0;
}
