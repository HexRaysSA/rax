#include <CoreServices/CoreServices.h>
#include <assert.h>
#include <dispatch/dispatch.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct subscription {
    const char *path;
    FSEventStreamEventFlags expected;
    dispatch_semaphore_t delivered;
};

static void on_events(ConstFSEventStreamRef stream, void *opaque, size_t count,
                      void *paths, const FSEventStreamEventFlags flags[],
                      const FSEventStreamEventId ids[]) {
    (void)stream;
    (void)ids;
    const struct subscription *state = opaque;
    const size_t path_length = strlen(state->path);
    const char data_root[] = "/System/Volumes/Data";
    char **names = paths;
    for (size_t index = 0; index < count; ++index) {
        const char *name = names[index];
        if (!strncmp(name, data_root, sizeof(data_root) - 1) &&
            name[sizeof(data_root) - 1] == '/') {
            name += sizeof(data_root) - 1;
        }
        bool matches = state->expected
            ? !strcmp(name, state->path) && (flags[index] & state->expected) == state->expected
            : !strncmp(name, state->path, path_length) &&
                (!name[path_length] || !strcmp(name + path_length, "/")) && flags[index] == 0;
        if (matches) {
            dispatch_semaphore_signal(state->delivered);
        }
    }
}

static void finish_callbacks(void *unused) {
    (void)unused;
}

static void check_creation(const char *prefix, bool file_events) {
    char directory_template[PATH_MAX];
    int length = snprintf(directory_template, sizeof(directory_template), "%s.XXXXXX", prefix);
    assert(length > 0 && (size_t)length < sizeof(directory_template));
    assert(mkdtemp(directory_template));
    char directory[PATH_MAX];
    assert(realpath(directory_template, directory));
    char path[PATH_MAX];
    length = snprintf(path, sizeof(path), "%s/created", directory);
    assert(length > 0 && (size_t)length < sizeof(path));

    struct subscription state = {
        .path = file_events ? path : directory,
        .expected = file_events
            ? kFSEventStreamEventFlagItemCreated | kFSEventStreamEventFlagItemIsFile
            : 0,
        .delivered = dispatch_semaphore_create(0),
    };
    FSEventStreamContext context = { .info = &state };
    CFStringRef name = CFStringCreateWithCString(NULL, directory, kCFStringEncodingUTF8);
    assert(name);
    const void *value = name;
    CFArrayRef paths = CFArrayCreate(NULL, &value, 1, &kCFTypeArrayCallBacks);
    assert(paths);
    FSEventStreamCreateFlags flags = kFSEventStreamCreateFlagNoDefer;
    if (file_events) {
        flags |= kFSEventStreamCreateFlagFileEvents;
    }
    FSEventStreamRef stream = FSEventStreamCreate(
        NULL, on_events, &context, paths, kFSEventStreamEventIdSinceNow, 0.05, flags);
    CFRelease(paths);
    CFRelease(name);
    assert(stream);
    dispatch_queue_t queue = dispatch_queue_create("rax.fsevents.control", DISPATCH_QUEUE_SERIAL);
    assert(queue);
    FSEventStreamSetDispatchQueue(stream, queue);
    assert(FSEventStreamStart(stream));

    int file = open(path, O_CREAT | O_EXCL | O_WRONLY, 0600);
    assert(file >= 0 && close(file) == 0);
    assert(dispatch_semaphore_wait(state.delivered,
                                   dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC)) == 0);

    FSEventStreamStop(stream);
    FSEventStreamInvalidate(stream);
    FSEventStreamRelease(stream);
    dispatch_sync_f(queue, NULL, finish_callbacks);
    dispatch_release(queue);
    dispatch_release(state.delivered);
    assert(unlink(path) == 0);
    assert(rmdir(directory) == 0);
}

int main(int argc, char **argv) {
    assert(argc == 2);
    check_creation(argv[1], true);
    check_creation(argv[1], false);
    puts("FSEvents file and directory creation delivered");
    return 0;
}
