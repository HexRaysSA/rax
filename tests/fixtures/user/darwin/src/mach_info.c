/* Host, task, thread, and VM kernel interfaces. Only machine-independent
 * facts are printed: result codes, counts, and relations. */
#include <errno.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

extern kern_return_t task_read_for_pid(mach_port_t, int, mach_port_t *);
extern kern_return_t task_inspect_for_pid(mach_port_t, int, mach_port_t *);

/* task_read_for_pid or task_inspect_for_pid on `pid`: the result, the
 * error, and whether a name came back. */
static void flavor_for_pid(const char *what, mach_port_t target, int pid, int read) {
    mach_port_t t = 0xdead;
    errno = 0;
    int r = read ? task_read_for_pid(target, pid, &t) : task_inspect_for_pid(target, pid, &t);
    printf("%s: %d errno=%d name=%s\n", what, r, r ? errno : 0,
           t == 0xdead ? "untouched" : t == MACH_PORT_NULL ? "null" : "set");
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    mach_port_t host = mach_host_self(), task = mach_task_self();
    integer_t buf[1024];
    mach_msg_type_number_t n;
    kern_return_t kr;

    /* host_info flavors and counts. */
    int flavors[] = { 0, 1, 3, 4, 5, 7, 8, 11, 12, 13 };
    for (unsigned i = 0; i < sizeof flavors / sizeof *flavors; i++) {
        n = 68;
        kr = host_info(host, flavors[i], buf, &n);
        printf("host_info(%d): kr=%#x count=%u\n", flavors[i], kr, kr ? 0 : n);
    }
    n = 5;
    printf("host_info basic old: kr=%#x count=%u\n", host_info(host, HOST_BASIC_INFO, buf, &n), n);
    n = 4;
    printf("host_info basic short: kr=%#x\n", host_info(host, HOST_BASIC_INFO, buf, &n));
    n = HOST_BASIC_INFO_COUNT;
    host_basic_info_data_t bi;
    host_info(host, HOST_BASIC_INFO, (host_info_t)&bi, &n);
    printf("basic: cpus_consistent=%d max_mem_nonzero=%d\n",
           bi.avail_cpus >= 1 && bi.avail_cpus <= bi.max_cpus && bi.logical_cpu == bi.avail_cpus,
           bi.max_mem != 0);
    n = HOST_PRIORITY_INFO_COUNT;
    host_priority_info_data_t pi;
    kr = host_info(host, HOST_PRIORITY_INFO, (host_info_t)&pi, &n);
    printf("priorities: kr=%#x user=%d kernel=%d max=%d\n", kr, pi.user_priority, pi.kernel_priority,
           pi.maximum_priority);
    n = HOST_SCHED_INFO_COUNT;
    host_sched_info_data_t si;
    kr = host_info(host, HOST_SCHED_INFO, (host_info_t)&si, &n);
    printf("sched: kr=%#x timeout=%d quantum=%d\n", kr, si.min_timeout, si.min_quantum);
    kernel_version_t version;
    kr = host_kernel_version(host, version);
    printf("kernel version: kr=%#x darwin=%d\n", kr, strncmp(version, "Darwin Kernel Version", 21) == 0);
    vm_size_t hps;
    kr = host_page_size(host, &hps);
    printf("host_page_size: kr=%#x power_of_two=%d\n", kr, hps && !(hps & (hps - 1)));
    n = 1024;
    printf("host_statistics bad flavor: kr=%#x\n", host_statistics(host, 99, buf, &n));

    /* task_info. */
    int tflavors[] = { 1, 2, 3, 4, 13, 14, 15, 16, 17, 20, 22, 28, 99 };
    for (unsigned i = 0; i < sizeof tflavors / sizeof *tflavors; i++) {
        n = 94;
        kr = task_info(task, tflavors[i], buf, &n);
        printf("task_info(%d): kr=%#x count=%u\n", tflavors[i], kr, kr ? 0 : n);
    }
    audit_token_t at;
    n = TASK_AUDIT_TOKEN_COUNT;
    task_info(task, TASK_AUDIT_TOKEN, (task_info_t)&at, &n);
    printf("audit token: pid_match=%d euid_match=%d pidversion_nonzero=%d\n",
           (pid_t)at.val[5] == getpid(), at.val[1] == geteuid(), at.val[7] != 0);
    struct task_dyld_info di;
    n = TASK_DYLD_INFO_COUNT;
    kr = task_info(task, TASK_DYLD_INFO, (task_info_t)&di, &n);
    printf("dyld info: kr=%#x format=%d has_address=%d\n", kr, di.all_image_info_format,
           di.all_image_info_addr != 0);
    n = 4;
    kr = task_info(task, TASK_DYLD_INFO, (task_info_t)&di, &n);
    printf("dyld info legacy: kr=%#x count=%u\n", kr, n);
    struct mach_task_basic_info mb;
    n = MACH_TASK_BASIC_INFO_COUNT;
    kr = task_info(task, MACH_TASK_BASIC_INFO, (task_info_t)&mb, &n);
    printf("basic: kr=%#x policy=%d suspend=%d resident_nonzero=%d\n", kr, mb.policy, mb.suspend_count,
           mb.resident_size != 0);

    /* Threads. */
    thread_act_array_t threads;
    mach_msg_type_number_t nthreads;
    kr = task_threads(task, &threads, &nthreads);
    mach_port_t self = mach_thread_self();
    /* Under Rosetta the translator runs a thread of its own, so only the
     * calling thread's presence is compared. */
    int found = 0;
    for (unsigned i = 0; i < nthreads; i++) found |= threads[i] == self;
    printf("task_threads: kr=%#x has_self=%d\n", kr, found);
    thread_basic_info_data_t tbi;
    n = THREAD_BASIC_INFO_COUNT;
    kr = thread_info(self, THREAD_BASIC_INFO, (thread_info_t)&tbi, &n);
    printf("thread basic: kr=%#x count=%u run_state=%d policy=%d\n", kr, n, tbi.run_state, tbi.policy);
    thread_identifier_info_data_t tii;
    n = THREAD_IDENTIFIER_INFO_COUNT;
    kr = thread_info(self, THREAD_IDENTIFIER_INFO, (thread_info_t)&tii, &n);
    uint64_t tid;
    pthread_threadid_np(NULL, &tid);
    printf("thread identifier: kr=%#x id_match=%d handle_match=%d\n", kr, tii.thread_id == tid,
           tii.thread_handle == (uint64_t)pthread_self());
    n = 32;
    kr = thread_info(self, THREAD_BASIC_INFO, (thread_info_t)buf, &n);
    printf("thread basic large count: kr=%#x count=%u\n", kr, n);
    n = 5;
    printf("thread basic short: kr=%#x\n", thread_info(self, THREAD_BASIC_INFO, (thread_info_t)buf, &n));
    n = 32;
    printf("thread_info bad flavor: kr=%#x\n", thread_info(self, 99, (thread_info_t)buf, &n));

    /* Special ports. */
    mach_port_t sp;
    kr = task_get_special_port(task, TASK_KERNEL_PORT, &sp);
    printf("special kernel port: kr=%#x is_task=%d\n", kr, sp == task);
    kr = task_get_special_port(task, TASK_HOST_PORT, &sp);
    printf("special host port: kr=%#x is_host=%d\n", kr, sp == host);
    kr = task_get_special_port(task, 99, &sp);
    printf("special bad: kr=%#x\n", kr);

    /* Flavored task ports: one port per flavor, so the same name each
     * time; for a pid, the caller's own and no other. */
    mach_port_t r1, r2, i1, i2, nm1, nm2, fp;
    kr = task_get_special_port(task, TASK_READ_PORT, &r1);
    task_get_special_port(task, TASK_READ_PORT, &r2);
    printf("read port: kr=%#x same=%d is_task=%d\n", kr, r1 == r2, r1 == task);
    kr = task_get_special_port(task, TASK_INSPECT_PORT, &i1);
    task_get_special_port(task, TASK_INSPECT_PORT, &i2);
    printf("inspect port: kr=%#x same=%d is_read=%d\n", kr, i1 == i2, i1 == r1);
    kr = task_get_special_port(task, TASK_NAME_PORT, &nm1);
    task_get_special_port(task, TASK_NAME_PORT, &nm2);
    printf("name port: kr=%#x same=%d\n", kr, nm1 == nm2);
    kr = task_read_for_pid(task, getpid(), &fp);
    printf("task_read_for_pid(self): kr=%d is_read=%d\n", kr, fp == r1);
    kr = task_inspect_for_pid(task, getpid(), &fp);
    printf("task_inspect_for_pid(self): kr=%d is_inspect=%d\n", kr, fp == i1);
    pid_t gone = fork();
    if (gone == 0) _exit(0);
    waitpid(gone, NULL, 0);
    for (int read = 1; read >= 0; read--) {
        printf("%s:\n", read ? "read" : "inspect");
        flavor_for_pid(" pid 0", task, 0, read);
        flavor_for_pid(" launchd", task, 1, read);
        flavor_for_pid(" parent", task, getppid(), read);
        flavor_for_pid(" reaped", task, gone, read);
        flavor_for_pid(" null target", MACH_PORT_NULL, getpid(), read);
        flavor_for_pid(" read port as target", r1, getpid(), read);
    }

    /* The host's special ports: the host port itself, the rest privileged
     * (a host_priv port is needed to set one). */
    sp = MACH_PORT_NULL;
    kr = host_get_special_port(host, HOST_LOCAL_NODE, HOST_PORT, &sp);
    printf("host special HOST_PORT: kr=%#x is_host=%d\n", kr, sp == host);
    for (int which = 2; which <= 12; which++) {
        sp = MACH_PORT_NULL;
        kr = host_get_special_port(host, HOST_LOCAL_NODE, which, &sp);
        printf(" host special %d: kr=%#x %s\n", which, kr, sp ? "set" : "null");
    }
    kr = host_get_special_port(host, 1, HOST_PORT, &sp);
    printf("host special on node 1: kr=%#x\n", kr);
    kr = host_set_special_port(host, 8, task);
    printf("host_set_special_port: kr=%#x\n", kr);

    /* VM. */
    mach_vm_address_t a = 0;
    kr = mach_vm_allocate(task, &a, 3 * 16384, VM_FLAGS_ANYWHERE | VM_MAKE_TAG(240));
    printf("allocate: kr=%#x\n", kr);
    kr = mach_vm_protect(task, a + 16384, 16384, 0, VM_PROT_READ);
    printf("protect: kr=%#x\n", kr);
    mach_vm_address_t ra = a;
    mach_vm_size_t rs = 0;
    vm_region_basic_info_data_64_t rb;
    mach_port_t obj;
    n = VM_REGION_BASIC_INFO_COUNT_64;
    kr = mach_vm_region(task, &ra, &rs, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&rb, &n, &obj);
    printf("region: kr=%#x starts_at=%d size_pages=%llu prot=%d max=%d inh=%d shared=%d count=%u obj_null=%d\n",
           kr, ra == a, (unsigned long long)(rs / 16384), rb.protection, rb.max_protection, rb.inheritance,
           rb.shared, n, obj == MACH_PORT_NULL);
    ra = a + 16384;
    kr = mach_vm_region(task, &ra, &rs, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&rb, &n, &obj);
    printf("region 2: kr=%#x prot=%d\n", kr, rb.protection);
    vm_region_submap_info_data_64_t sub;
    natural_t depth = 0;
    ra = a;
    n = VM_REGION_SUBMAP_INFO_COUNT_64;
    kr = mach_vm_region_recurse(task, &ra, &rs, &depth, (vm_region_recurse_info_t)&sub, &n);
    printf("recurse: kr=%#x count=%u tag=%u prot=%d\n", kr, n, sub.user_tag, sub.protection);
    char src[64], dst[64];
    memset(src, 'x', sizeof src);
    mach_vm_size_t outsz = 0;
    kr = mach_vm_read_overwrite(task, (mach_vm_address_t)src, sizeof src, (mach_vm_address_t)dst, &outsz);
    printf("read_overwrite: kr=%#x size=%llu same=%d\n", kr, (unsigned long long)outsz, memcmp(src, dst, 64) == 0);
    kr = mach_vm_write(task, a + 16384, (vm_offset_t)src, sizeof src);
    printf("write to read-only: kr=%#x\n", kr);
    kr = mach_vm_write(task, a, (vm_offset_t)src, sizeof src);
    printf("write: kr=%#x same=%d\n", kr, memcmp((void *)a, src, sizeof src) == 0);
    kr = mach_vm_deallocate(task, a, 3 * 16384);
    printf("deallocate: kr=%#x\n", kr);
    ra = a;
    n = VM_REGION_BASIC_INFO_COUNT_64;
    kr = mach_vm_region(task, &ra, &rs, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&rb, &n, &obj);
    printf("region after deallocate: kr=%#x moved_on=%d\n", kr, kr || ra > a);
    kr = mach_vm_protect(task, a, 16384, 0, VM_PROT_READ);
    printf("protect unmapped: kr=%#x\n", kr);
    return 0;
}
