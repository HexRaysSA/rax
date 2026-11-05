/* SDK-only DEBUGCTL access and branch-step observations. No RAX is linked.
 * Intel SDM Vol. 3B 19.4.1/19.4.3 and Vol. 3C 28.3.2 define the controls;
 * the report records SDK behavior without assuming the SDK delegates MSRs.
 */
#define RAX_RAM_ENTRY_NO_MAIN
#include "intel_ram_entry_native.c"

static const char *const cases[] = {
    "read-msr", "write-zero", "write-btf", "tf", "btf-default-entry", "btf-load-entry",
};

static void optional_field(hv_vcpuid_t cpu, const char *name, uint32_t id)
{
    uint64_t value = 0;
    hv_return_t status = hv_vmx_vcpu_read_vmcs(cpu, id, &value);
    printf(",\"%s\":{\"status\":%u,\"value\":", name, (uint32_t)status);
    if (status == HV_SUCCESS) printf("%" PRIu64, value); else printf("null");
    printf("}");
}

static void debug_snapshot(hv_vcpuid_t cpu)
{
    printf("{\"core\":");
    snapshot(cpu);
    printf(",\"dr6\":%" PRIu64 ",\"rdx\":%" PRIu64,
           read_reg(cpu, HV_X86_DR6), read_reg(cpu, HV_X86_RDX));
    optional_field(cpu, "debugctl", 0x2802);
    optional_field(cpu, "exit_controls", 0x400c);
    optional_field(cpu, "pending_debug", 0x6822);
    optional_field(cpu, "exit_qualification", 0x6400);
    optional_field(cpu, "exit_interrupt_info", 0x4404);
    optional_field(cpu, "instruction_error", 0x4400);
    printf("}");
}

int main(int argc, char **argv)
{
    size_t selected = sizeof(cases) / sizeof(cases[0]);
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        if (argc == 2 && strcmp(argv[1], cases[i]) == 0) selected = i;
    }
    if (selected == sizeof(cases) / sizeof(cases[0])) return 2;
    int preflight = availability_main();
    if (preflight != 0) return preflight;
    check(hv_vm_create(HV_VM_DEFAULT), "create VM");
    uint8_t *memory = mmap(NULL, RAM, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANON, -1, 0);
    if (memory == MAP_FAILED) return 1;
    populate(memory);
    if (selected < 3) {
        /* RDMSR/WRMSR; MOV R10, marker; HLT. */
        memmove(memory + CODE + 2, memory + CODE, 11);
        memory[CODE] = 0x0f;
        memory[CODE + 1] = selected == 0 ? 0x32 : 0x30;
    } else {
        /* A taken branch immediately after MOV distinguishes TF from BTF. */
        memory[CODE + 10] = 0xeb;
        memory[CODE + 11] = 0;
        memory[CODE + 12] = 0xf4;
    }
    check(hv_vm_map(memory, 0, RAM, HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC),
          "map guest RAM");
    hv_vcpuid_t cpu;
    check(hv_vcpu_create(&cpu, HV_VCPU_DEFAULT), "create CPU");
    uint64_t initial_bitmap = read_field(cpu, 0x4004);
    controls(cpu);
    constructor(cpu, 7);
    setup(cpu, &variants[1]); /* Previously qualified full CR masks/shadows. */
    /* Observe #DB and #GP while retaining the SDK's original intercepts. */
    field(cpu, 0x4004, initial_bitmap | (1u << 1) | (1u << 13));
    reg(cpu, HV_X86_RCX, 0x1d9);
    reg(cpu, HV_X86_RAX, selected == 2 ? 2 : 0);
    reg(cpu, HV_X86_RDX, 0);
    reg(cpu, HV_X86_RFLAGS, selected >= 3 ? 0x102 : 2);
    uint64_t requested_debugctl = selected >= 4 ? 2 : 0;
    hv_return_t config_status = hv_vmx_vcpu_write_vmcs(cpu, 0x2802, requested_debugctl);
    if (config_status == HV_SUCCESS && selected == 5) {
        /* Capture rejection as an observation rather than bypassing SDK constraints. */
        config_status = hv_vmx_vcpu_write_vmcs(cpu, ENTRY, read_field(cpu, ENTRY) | 4);
    }
    printf("{\"probe\":\"debugctl\",\"version\":1,\"case\":\"%s\","
           "\"initial_exception_bitmap\":%" PRIu64 ",\"exception_bitmap\":%" PRIu64
           ",\"requested_debugctl\":%" PRIu64 ",\"configuration_status\":%u,\"before\":",
           cases[selected], initial_bitmap, read_field(cpu, 0x4004), requested_debugctl,
           (uint32_t)config_status);
    debug_snapshot(cpu);
    fflush(stdout);
    mach_timebase_info_data_t timebase;
    if (mach_timebase_info(&timebase) != KERN_SUCCESS || timebase.numer == 0) return 1;
    uint64_t ticks = UINT64_C(100000000) * timebase.denom / timebase.numer;
    hv_return_t status = HV_SUCCESS;
    uint64_t reason = 0;
    size_t entries = 0;
    if (config_status == HV_SUCCESS) {
        do {
            uint64_t now = mach_absolute_time();
            if (ticks > UINT64_MAX - now) return 1;
            status = hv_vcpu_run_until(cpu, now + ticks);
            entries++;
            if (status != HV_SUCCESS) break;
            reason = read_field(cpu, EXIT_REASON);
        } while ((reason == 52 || reason == 1) && entries < 10);
    }
    printf(",\"after\":");
    debug_snapshot(cpu);
    printf(",\"guest_entry_attempted\":%s,\"entries\":%zu,\"run_status\":",
           entries != 0 ? "true" : "false", entries);
    if (entries != 0) printf("%u", (uint32_t)status); else printf("null");
    printf(",\"exit_reason\":");
    if (entries != 0 && status == HV_SUCCESS) printf("%" PRIu64, reason);
    else printf("null");
    hv_return_t cpu_destroy = hv_vcpu_destroy(cpu);
    hv_return_t unmap = hv_vm_unmap(0, RAM);
    hv_return_t vm_destroy = hv_vm_destroy();
    int host_unmap = munmap(memory, RAM);
    printf(",\"vcpu_destroy_status\":%u,\"guest_unmap_status\":%u,"
           "\"vm_destroy_status\":%u,\"host_unmap_status\":%d}\n",
           (uint32_t)cpu_destroy, (uint32_t)unmap, (uint32_t)vm_destroy, host_unmap);
    return cpu_destroy == HV_SUCCESS && unmap == HV_SUCCESS &&
           vm_destroy == HV_SUCCESS && host_unmap == 0 ? 0 : 1;
}
