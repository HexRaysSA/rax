// CoreServices and the memory its services share with the process: the
// session's file-ID universe, which coreservicesd maps into the task (FSRef
// calls reach it), Launch Services database lookups, and the session's
// shared memory page lsd hands over, which Launch Services maps and then
// remaps; in the process and in a spawned child (a new image, which hands
// its task to coreservicesd again).
// link: -framework CoreServices
#include <CoreServices/CoreServices.h>
#include <mach-o/dyld.h>
#include <spawn.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>

extern char **environ;
extern CFTypeRef _LSGetCurrentApplicationASN(void);
extern CFTypeRef _LSCopyApplicationInformationItem(int, CFTypeRef, CFStringRef);

static void node(const char *who, const char *path) {
    FSRef ref;
    OSStatus st = FSPathMakeRef((const UInt8 *)path, &ref, NULL);
    UInt8 back[1024] = {0};
    OSStatus made = st ? st : FSRefMakePath(&ref, back, sizeof back);
    FSCatalogInfo info;
    HFSUniStr255 name;
    OSStatus cat = st ? st : FSGetCatalogInfo(&ref, kFSCatInfoNodeFlags, &info, &name, NULL, NULL);
    printf("%s: %s: ref %d path %d %s catalog %d dir=%d name=%d\n", who, path, (int)st, (int)made, back, (int)cat,
           cat ? -1 : (info.nodeFlags & kFSNodeIsDirectoryMask) != 0, cat ? -1 : name.length);
}

static void run(const char *who) {
    node(who, "/usr/bin");
    node(who, "/private/etc/hosts");
    node(who, "/no/such/path");

    CFURLRef url = CFURLCreateWithFileSystemPath(NULL, CFSTR("/System/Applications/TextEdit.app"),
                                                 kCFURLPOSIXPathStyle, true);
    CFStringRef kind = NULL;
    OSStatus st = LSCopyKindStringForURL(url, &kind);
    char text[256] = "";
    if (kind) CFStringGetCString(kind, text, sizeof text, kCFStringEncodingUTF8);
    printf("%s: kind %d %s\n", who, (int)st, text);

    // Through the session's shared memory page.
    CFTypeRef asn = _LSGetCurrentApplicationASN();
    CFTypeRef item = _LSCopyApplicationInformationItem(-2, asn, CFSTR("CFBundleIdentifier"));
    printf("%s: application information asn=%d bundle id=%d\n", who, asn != NULL, item != NULL);
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc == 2) {
        run(argv[1]);
        return 0;
    }
    run("parent");
    char self[4096];
    uint32_t len = sizeof self;
    _NSGetExecutablePath(self, &len);
    char *args[] = {self, "spawned child", NULL};
    pid_t pid;
    int status = -1;
    if (posix_spawn(&pid, self, NULL, NULL, args, environ) == 0) waitpid(pid, &status, 0);
    printf("child: %d\n", status);
    return 0;
}
