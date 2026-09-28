// mach_vm_remap and mach_vm_remap_new on the task's own memory: shared
// aliases (stores through either mapping seen through the other) and
// copies, the protections each reports and gives, the attributes the new
// mapping takes, the page rounding of each, placement, and the refusals.
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static mach_port_t self;
static mach_vm_size_t page;

// The protections, inheritance, sharing, and user tag of the region at
// `addr`, and whether it starts there and how many pages it spans.
static void region(const char *what, mach_vm_address_t addr) {
    mach_vm_address_t a = addr;
    mach_vm_size_t size = 0;
    natural_t depth = 0;
    vm_region_submap_info_data_64_t info;
    mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
    kern_return_t kr = mach_vm_region_recurse(self, &a, &size, &depth, (vm_region_recurse_info_t)&info, &count);
    if (kr) {
        printf("%s: region %d\n", what, kr);
        return;
    }
    vm_region_basic_info_data_64_t basic;
    mach_vm_address_t b = addr;
    mach_vm_size_t bsize = 0;
    mach_port_t obj = MACH_PORT_NULL;
    count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_vm_region(self, &b, &bsize, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&basic, &count, &obj);
    printf("%s: at=%d pages=%llu prot=%d/%d inherit=%d shared=%d tag=%u\n", what, a == addr,
           (unsigned long long)(size / page), info.protection, info.max_protection, info.inheritance, basic.shared,
           info.user_tag);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    self = mach_task_self();
    page = (mach_vm_size_t)getpagesize();

    // The source: two tagged pages, the second made read-only.
    mach_vm_address_t src = 0;
    kern_return_t kr = mach_vm_allocate(self, &src, 2 * page, VM_FLAGS_ANYWHERE | VM_MAKE_TAG(242));
    printf("allocate: %d\n", kr);
    strcpy((char *)src, "first");
    strcpy((char *)src + page, "second");
    mach_vm_protect(self, src + page, page, FALSE, VM_PROT_READ);

    // A shared remap reports the strictest protections and keeps each
    // part's own; the alias and the source are one memory.
    mach_vm_address_t a = 0;
    vm_prot_t cur = -1, max = -1;
    kr = mach_vm_remap(self, &a, 2 * page, 0, VM_FLAGS_ANYWHERE, self, src, FALSE, &cur, &max, VM_INHERIT_SHARE);
    printf("remap shared: %d cur=%d max=%d elsewhere=%d aligned=%d\n", kr, cur, max, a != src, (a & (page - 1)) == 0);
    printf("contents: %s %s\n", (char *)a, (char *)a + page);
    strcpy((char *)src, "FIRST");
    printf("the alias sees: %s\n", (char *)a);
    strcpy((char *)a, "alias");
    printf("the source sees: %s\n", (char *)src);
    region("alias", a);
    region("alias page 2", a + page);
    region("source", src);

    // A copy does not see later stores.
    mach_vm_address_t c = 0;
    kr = mach_vm_remap(self, &c, page, 0, VM_FLAGS_ANYWHERE, self, src, TRUE, &cur, &max, VM_INHERIT_COPY);
    strcpy((char *)src, "changed");
    printf("remap copy: %d cur=%d max=%d contents=%s\n", kr, cur, max, kr ? "" : (char *)c);
    region("copy", c);

    // The legacy rounding: the start truncated, the size rounded alone.
    mach_vm_address_t r = 0;
    kr = mach_vm_remap(self, &r, 0x20, 0, VM_FLAGS_ANYWHERE, self, src + page - 0x10, FALSE, &cur, &max,
                       VM_INHERIT_SHARE);
    printf("legacy rounding: %d aligned=%d\n", kr, (r & (page - 1)) == 0);
    region("legacy rounding", r);

    // mach_vm_remap_new returns the data's address and covers each page
    // the range touches, with the protections asked for.
    mach_vm_address_t n = 0;
    cur = VM_PROT_READ;
    max = VM_PROT_READ;
    kr = mach_vm_remap_new(self, &n, 0x20, 0, VM_FLAGS_ANYWHERE, self, src + page - 0x10, FALSE, &cur, &max,
                           VM_INHERIT_NONE);
    printf("remap_new: %d offset=%#llx cur=%d max=%d\n", kr, (unsigned long long)(n & (page - 1)), cur, max);
    region("remap_new", n & ~(page - 1));
    // It needs those protections of the source (a copy only readable
    // memory).
    mach_vm_address_t n2 = 0;
    cur = VM_PROT_READ | VM_PROT_WRITE;
    max = cur;
    kr = mach_vm_remap_new(self, &n2, page, 0, VM_FLAGS_ANYWHERE, self, src + page, FALSE, &cur, &max,
                           VM_INHERIT_SHARE);
    printf("remap_new of read-only memory for writing: %d\n", kr);
    cur = VM_PROT_READ | VM_PROT_WRITE;
    max = cur;
    kr = mach_vm_remap_new(self, &n2, page, 0, VM_FLAGS_ANYWHERE, self, src + page, TRUE, &cur, &max,
                           VM_INHERIT_SHARE);
    printf("remap_new copy of it for writing: %d cur=%d max=%d\n", kr, cur, max);
    if (kr == KERN_SUCCESS) {
        strcpy((char *)n2, "written");
        printf("the copy is writable: %s, the source %s\n", (char *)n2, (char *)src + page);
    }
    cur = VM_PROT_READ;
    max = VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE;
    kr = mach_vm_remap_new(self, &n2, page, 0, VM_FLAGS_ANYWHERE, self, src, FALSE, &cur, &max, VM_INHERIT_SHARE);
    printf("remap_new writable and executable: %d\n", kr);
    cur = VM_PROT_READ | VM_PROT_WRITE;
    max = VM_PROT_READ;
    kr = mach_vm_remap_new(self, &n2, page, 0, VM_FLAGS_ANYWHERE, self, src, FALSE, &cur, &max, VM_INHERIT_SHARE);
    printf("remap_new cur beyond max: %d\n", kr);

    // The task's read port names readable memory for mach_vm_remap_new,
    // but not for mach_vm_remap.
    mach_port_t rp = MACH_PORT_NULL;
    kr = task_get_special_port(self, TASK_READ_PORT, &rp);
    printf("read port: %d\n", kr);
    cur = VM_PROT_READ;
    max = VM_PROT_READ;
    kr = mach_vm_remap_new(self, &n2, page, 0, VM_FLAGS_ANYWHERE, rp, src, FALSE, &cur, &max, VM_INHERIT_SHARE);
    printf("remap_new from the read port, readable: %d\n", kr);
    cur = VM_PROT_READ | VM_PROT_WRITE;
    max = cur;
    kr = mach_vm_remap_new(self, &n2, page, 0, VM_FLAGS_ANYWHERE, rp, src, FALSE, &cur, &max, VM_INHERIT_SHARE);
    printf("remap_new from the read port, writable: %d\n", kr);
    kr = mach_vm_remap(self, &n2, page, 0, VM_FLAGS_ANYWHERE, rp, src, FALSE, &cur, &max, VM_INHERIT_SHARE);
    printf("remap from the read port: %d\n", kr);

    // Placement: fixed where memory is, and over it.
    mach_vm_address_t f = c;
    kr = mach_vm_remap(self, &f, page, 0, VM_FLAGS_FIXED, self, src, FALSE, &cur, &max, VM_INHERIT_SHARE);
    printf("fixed over memory: %d\n", kr);
    kr = mach_vm_remap(self, &f, page, 0, VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE, self, src, FALSE, &cur, &max,
                       VM_INHERIT_SHARE);
    printf("fixed overwriting: %d same=%d contents=%s\n", kr, f == c, kr ? "" : (char *)f);

    // Refusals.
    mach_vm_address_t x = 0;
    kr = mach_vm_remap(self, &x, page, 0, VM_FLAGS_ANYWHERE | VM_FLAGS_PURGABLE, self, src, FALSE, &cur, &max,
                       VM_INHERIT_SHARE);
    printf("purgable: %d\n", kr);
    kr = mach_vm_remap(self, &x, 0, 0, VM_FLAGS_ANYWHERE, self, src, FALSE, &cur, &max, VM_INHERIT_SHARE);
    printf("empty: %d\n", kr);
    kr = mach_vm_remap(self, &x, page, 0, VM_FLAGS_ANYWHERE, self, src, FALSE, &cur, &max, 3);
    printf("bad inheritance: %d\n", kr);
    kr = mach_vm_remap(self, &x, page, 0, VM_FLAGS_ANYWHERE | VM_FLAGS_RESILIENT_MEDIA, self, src, FALSE, &cur,
                       &max, VM_INHERIT_SHARE);
    printf("resilient media, shared: %d\n", kr);
    mach_vm_address_t hole = 0;
    mach_vm_allocate(self, &hole, 3 * page, VM_FLAGS_ANYWHERE);
    mach_vm_deallocate(self, hole + page, page);
    kr = mach_vm_remap(self, &x, 3 * page, 0, VM_FLAGS_ANYWHERE, self, hole, FALSE, &cur, &max, VM_INHERIT_SHARE);
    printf("across a hole: %d\n", kr);
    kr = mach_vm_remap(self, &x, page, 0, VM_FLAGS_ANYWHERE, self, 0, FALSE, &cur, &max, VM_INHERIT_SHARE);
    printf("page zero: %d\n", kr);
    kr = mach_vm_remap(rp, &x, page, 0, VM_FLAGS_ANYWHERE, self, src, FALSE, &cur, &max, VM_INHERIT_SHARE);
    printf("into the read port: %d\n", kr);
    return 0;
}
