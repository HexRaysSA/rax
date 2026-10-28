/* Manipulate a stopped tracee's virtual address space through its task port. */
#include <errno.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void) {
    int ready[2], gate[2];
    if (pipe(ready) || pipe(gate)) return 1;
    pid_t child = fork();
    if (child < 0) return 1;
    if (child == 0) {
        close(ready[0]); close(gate[1]);
        char byte;
        if (write(ready[1], "r", 1) != 1) _exit(90);
        ssize_t n;
        do { n = read(gate[0], &byte, 1); } while (n < 0 && errno == EINTR);
        _exit(n == 1 ? 42 : 91);
    }
    close(ready[1]); close(gate[0]);
    char byte;
    int status;
    if (read(ready[0], &byte, 1) != 1 || ptrace(PT_ATTACH, child, 0, 0) ||
        waitpid(child, &status, 0) != child || !WIFSTOPPED(status)) goto fail;
    mach_port_t task = MACH_PORT_NULL;
    if (task_for_pid(mach_task_self(), child, &task) != KERN_SUCCESS) goto fail;
    thread_act_array_t threads = NULL;
    mach_msg_type_number_t thread_count = 0;
    kern_return_t listed = task_threads(task, &threads, &thread_count);
    int thread_info_valid = listed == KERN_SUCCESS && thread_count > 0;
    for (mach_msg_type_number_t i = 0; i < thread_count; i++) {
        thread_basic_info_data_t basic = {0};
        mach_msg_type_number_t basic_count = THREAD_BASIC_INFO_COUNT;
        kern_return_t basic_result = thread_info(threads[i], THREAD_BASIC_INFO,
                                                  (thread_info_t)&basic, &basic_count);
        thread_identifier_info_data_t identity = {0};
        mach_msg_type_number_t identity_count = THREAD_IDENTIFIER_INFO_COUNT;
        kern_return_t identity_result = thread_info(threads[i], THREAD_IDENTIFIER_INFO,
                                                     (thread_info_t)&identity, &identity_count);
        thread_info_valid &= basic_result == KERN_SUCCESS && basic_count == THREAD_BASIC_INFO_COUNT &&
                             identity_result == KERN_SUCCESS && identity_count == THREAD_IDENTIFIER_INFO_COUNT &&
                             identity.thread_id != 0;
        mach_port_deallocate(mach_task_self(), threads[i]);
    }
    if (threads) vm_deallocate(mach_task_self(), (vm_address_t)threads, thread_count * sizeof(*threads));
    printf("threads=%d info=%d\n", listed, thread_info_valid);
    audit_token_t audit = {0};
    mach_msg_type_number_t audit_count = TASK_AUDIT_TOKEN_COUNT;
    kern_return_t audit_result = task_info(task, TASK_AUDIT_TOKEN, (task_info_t)&audit, &audit_count);
    mach_msg_type_number_t short_count = 1;
    kern_return_t short_result = task_info(task, TASK_AUDIT_TOKEN, (task_info_t)&audit, &short_count);
    task_dyld_info_data_t dyld = {0};
    mach_msg_type_number_t dyld_count = TASK_DYLD_INFO_COUNT;
    kern_return_t dyld_result = task_info(task, TASK_DYLD_INFO, (task_info_t)&dyld, &dyld_count);
    printf("audit=%d pid=%d short=%d dyld=%d address=%d\n", audit_result,
           audit.val[5] == (unsigned)child, short_result, dyld_result, dyld.all_image_info_addr != 0);
    mach_vm_address_t region = 0;
    kern_return_t a = mach_vm_allocate(task, &region, 4096, VM_FLAGS_ANYWHERE);
    uint64_t value = UINT64_C(0x1122334455667788), got = 0;
    kern_return_t w = mach_vm_write(task, region, (vm_offset_t)&value, sizeof(value));
    mach_vm_address_t found = region;
    mach_vm_size_t length = 0;
    vm_region_basic_info_data_64_t basic;
    mach_msg_type_number_t basic_count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object = MACH_PORT_NULL;
    kern_return_t region_result = mach_vm_region(task, &found, &length, VM_REGION_BASIC_INFO_64,
                                                 (vm_region_info_t)&basic, &basic_count, &object);
    int contains = region_result == KERN_SUCCESS && found <= region && region - found < length;
    int writable = region_result == KERN_SUCCESS && (basic.protection & (VM_PROT_READ | VM_PROT_WRITE)) == (VM_PROT_READ | VM_PROT_WRITE);
    int object_null = object == MACH_PORT_NULL;
    if (object != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), object);
    mach_vm_address_t nested = region;
    mach_vm_size_t nested_length = 0;
    natural_t depth = 0;
    vm_region_submap_info_data_64_t submap;
    mach_msg_type_number_t submap_count = VM_REGION_SUBMAP_INFO_COUNT_64;
    kern_return_t recurse = mach_vm_region_recurse(task, &nested, &nested_length, &depth,
                                                   (vm_region_recurse_info_t)&submap, &submap_count);
    int nested_contains = recurse == KERN_SUCCESS && nested <= region && region - nested < nested_length;
    int nested_writable = recurse == KERN_SUCCESS && (submap.protection & (VM_PROT_READ | VM_PROT_WRITE)) == (VM_PROT_READ | VM_PROT_WRITE);
    int disposition = 0, references = 0;
    kern_return_t page = mach_vm_page_query(task, region, &disposition, &references);
    kern_return_t c = mach_vm_copy(task, region, sizeof(value), region + 16);
    mach_vm_size_t count = 0;
    kern_return_t r = mach_vm_read_overwrite(task, region + 16, sizeof(got), (mach_vm_address_t)&got, &count);
    kern_return_t p = mach_vm_protect(task, region, 4096, FALSE, VM_PROT_READ);
    kern_return_t blocked = mach_vm_write(task, region, (vm_offset_t)&value, sizeof(value));
    kern_return_t restore = mach_vm_protect(task, region, 4096, FALSE, VM_PROT_READ | VM_PROT_WRITE);
    kern_return_t d = mach_vm_deallocate(task, region, 4096);
    kern_return_t missing = mach_vm_read_overwrite(task, region, sizeof(got), (mach_vm_address_t)&got, &count);
    printf("alloc=%d valid=%d write=%d copy=%d read=%d count=%llu value=%016llx\n",
           a, region != 0, w, c, r, (unsigned long long)count, (unsigned long long)got);
    printf("region=%d contains=%d writable=%d object-null=%d recurse=%d contains=%d writable=%d\n",
           region_result, contains, writable, object_null, recurse, nested_contains, nested_writable);
    printf("page=%d present=%d\n", page, !!(disposition & VM_PAGE_QUERY_PAGE_PRESENT));
    printf("protect=%d blocked=%d restore=%d dealloc=%d missing=%d\n", p, blocked, restore, d, missing);
    if (ptrace(PT_CONTINUE, child, (caddr_t)1, 0) || write(gate[1], "x", 1) != 1 ||
        waitpid(child, &status, 0) != child) goto fail;
    return !thread_info_valid || audit_result || audit.val[5] != (unsigned)child || short_result != KERN_INVALID_ARGUMENT ||
           dyld_result || !dyld.all_image_info_addr || a || w || c || r || region_result || recurse || page || p || restore || d ||
           !WIFEXITED(status) || WEXITSTATUS(status) != 42;
fail:
    kill(child, SIGKILL);
    ptrace(PT_CONTINUE, child, (caddr_t)1, 0);
    waitpid(child, NULL, 0);
    return 1;
}
