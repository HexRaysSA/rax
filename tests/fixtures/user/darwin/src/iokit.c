// IOKit through the host's IOKit main port: matching, the registry's
// names, IDs, and paths, and properties read into the caller's buffers
// (the platform's UUID is the machine's, as gethostuuid gives it).
// link: -framework IOKit -framework CoreFoundation
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <uuid/uuid.h>

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    mach_port_t mainp = MACH_PORT_NULL;
    kern_return_t kr = IOMainPort(MACH_PORT_NULL, &mainp);
    printf("main port: %d valid=%d\n", kr, MACH_PORT_VALID(mainp));

    io_registry_entry_t root = IORegistryGetRootEntry(mainp);
    io_name_t name;
    kr = IORegistryEntryGetName(root, name);
    printf("root: valid=%d name %d %s\n", root != 0, kr, name);
    CFMutableDictionaryRef props = NULL;
    kr = IORegistryEntryCreateCFProperties(root, &props, kCFAllocatorDefault, 0);
    printf("root properties: %d count>0=%d\n", kr, props && CFDictionaryGetCount(props) > 0);
    if (props) CFRelease(props);

    io_service_t pe = IOServiceGetMatchingService(mainp, IOServiceMatching("IOPlatformExpertDevice"));
    printf("platform expert: valid=%d conforms=%d\n", pe != 0, pe && IOObjectConformsTo(pe, "IOService"));
    uint64_t id = 0;
    kr = IORegistryEntryGetRegistryEntryID(pe, &id);
    printf("entry id: %d nonzero=%d\n", kr, id != 0);
    io_string_t path;
    kr = IORegistryEntryGetPath(pe, kIOServicePlane, path);
    printf("path: %d %s\n", kr, path);
    io_name_t cls;
    IOObjectGetClass(pe, cls);
    printf("class: %s\n", cls);

    // The platform UUID, read into a buffer of the caller's.
    CFTypeRef u = IORegistryEntryCreateCFProperty(pe, CFSTR("IOPlatformUUID"), kCFAllocatorDefault, 0);
    char text[64] = "";
    if (u && CFGetTypeID(u) == CFStringGetTypeID()) CFStringGetCString(u, text, sizeof text, kCFStringEncodingUTF8);
    uuid_t host;
    struct timespec ts = {1, 0};
    gethostuuid(host, &ts);
    char want[40];
    uuid_unparse_upper(host, want);
    printf("platform UUID: present=%d matches gethostuuid=%d\n", u != NULL, strcmp(text, want) == 0);
    if (u) CFRelease(u);
    CFTypeRef missing = IORegistryEntryCreateCFProperty(pe, CFSTR("NoSuchPropertyForRax"), kCFAllocatorDefault, 0);
    printf("missing property: %s\n", missing ? "present" : "none");

    // Iterating: the platform expert's children.
    io_iterator_t it = 0;
    kr = IORegistryEntryGetChildIterator(pe, kIOServicePlane, &it);
    int children = 0;
    io_object_t o;
    while ((o = IOIteratorNext(it))) {
        children++;
        IOObjectRelease(o);
    }
    printf("children: %d any=%d\n", kr, children > 0);
    IOObjectRelease(it);
    IOObjectRelease(pe);
    io_service_t none = IOServiceGetMatchingService(mainp, IOServiceMatching("NoSuchClassForRax"));
    printf("no match: %d\n", none);
    return 0;
}
