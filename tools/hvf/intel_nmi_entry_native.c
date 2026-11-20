/* SDK-only control for VM-entry event admission. No RAX library is linked. */
#define RAX_RAM_ENTRY_NO_MAIN
#include "intel_ram_entry_native.c"

enum {
    PIN_CONTROLS = 0x4000, ENTRY_EVENT = 0x4016, EXIT_QUAL = 0x6400,
    IDT_BASE = 0x6818, IDT_LIMIT = 0x4812, INTERRUPTIBILITY = 0x4824,
    IDT = 0xc000, HANDLER = 0xb000, IRQ_VECTOR = 0x40,
    START_PORT = 0x81, HANDLER_PORT = 0x80,
};

enum event { NONE, IRQ, NMI };
static const char *const names[] = {"none", "irq", "nmi"};

static void publish_gate(uint8_t *memory, unsigned vector)
{
    word(memory, IDT + 16 * vector,
         HANDLER | (UINT64_C(8) << 16) | (UINT64_C(0x8e) << 40));
    word(memory, IDT + 16 * vector + 8, 0);
}

static uint64_t enter(hv_vcpuid_t cpu, uint64_t slice)
{
    for (unsigned attempt = 0; attempt < 10; attempt++) {
        check(hv_vcpu_run_until(cpu, mach_absolute_time() + slice), "run guest");
        uint64_t reason = read_field(cpu, EXIT_REASON);
        if (reason != 1 && reason != 52) return reason;
    }
    fprintf(stderr, "ten SDK entries exhausted without a guest exit\n");
    exit(1);
}

static bool port_exit(hv_vcpuid_t cpu, uint64_t reason, unsigned port)
{
    return reason == 30 && (read_field(cpu, EXIT_QUAL) >> 16 & 0xffff) == port;
}

int main(int argc, char **argv)
{
    if (argc != 2) return 2;
    enum event event;
    if (strcmp(argv[1], names[NONE]) == 0) event = NONE;
    else if (strcmp(argv[1], names[IRQ]) == 0) event = IRQ;
    else if (strcmp(argv[1], names[NMI]) == 0) event = NMI;
    else return 2;

    int preflight = availability_main();
    if (preflight != 0) return preflight;
    check(hv_vm_create(HV_VM_DEFAULT), "create VM");
    uint8_t *memory = mmap(NULL, RAM, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANON, -1, 0);
    if (memory == MAP_FAILED) return 1;
    populate(memory);
    memmove(memory + CODE + 2, memory + CODE, 11);
    const uint8_t marker[] = {0xe6, START_PORT};
    const uint8_t handler[] = {0x49, 0xff, 0xc3, 0xe6, HANDLER_PORT, 0x48, 0xcf};
    memcpy(memory + CODE, marker, sizeof(marker));
    memcpy(memory + HANDLER, handler, sizeof(handler));
    publish_gate(memory, 2);
    publish_gate(memory, IRQ_VECTOR);
    check(hv_vm_map(memory, 0, RAM, HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC),
          "map guest RAM");
    hv_vcpuid_t cpu;
    check(hv_vcpu_create(&cpu, HV_VCPU_DEFAULT), "create CPU");
    uint64_t bitmap = read_field(cpu, 0x4004);
    controls(cpu);
    constructor(cpu, 7);
    setup(cpu, &variants[1]);
    field(cpu, 0x4004, bitmap);
    field(cpu, IDT_BASE, IDT);
    field(cpu, IDT_LIMIT, (IRQ_VECTOR + 1) * 16 - 1);
    uint64_t caps = 0;
    check(hv_vmx_read_capability(HV_VMX_CAP_PINBASED, &caps), "read pin capability");
    uint64_t pins = read_field(cpu, PIN_CONTROLS) | 1 | (1 << 3) | (1 << 5);
    if ((pins & ~(caps >> 32)) != 0) {
        fprintf(stderr, "virtual NMI pin controls unavailable\n");
        return 1;
    }
    field(cpu, PIN_CONTROLS, pins);
    const uint64_t initial_flags = event == IRQ ? 0x202 : 2;
    reg(cpu, HV_X86_RFLAGS, initial_flags);
    reg(cpu, HV_X86_R11, 0);
    mach_timebase_info_data_t timebase;
    if (mach_timebase_info(&timebase) != KERN_SUCCESS || timebase.numer == 0) return 1;
    uint64_t slice = UINT64_C(100000000) * timebase.denom / timebase.numer;
    uint64_t initial_exit = enter(cpu, slice);
    if (!port_exit(cpu, initial_exit, START_PORT) || read_reg(cpu, HV_X86_RIP) != CODE) {
        fprintf(stderr, "initial marker missing, exit=%#" PRIx64 "\n", initial_exit);
        return 1;
    }
    reg(cpu, HV_X86_RIP, CODE + sizeof(marker));

    uint64_t entry_event = 0;
    if (event == IRQ) entry_event = UINT64_C(0x80000000) | IRQ_VECTOR;
    if (event == NMI) entry_event = UINT64_C(0x80000202);
    field(cpu, ENTRY_EVENT, entry_event);
    uint64_t staged = read_field(cpu, ENTRY_EVENT);
    uint64_t shadow = read_field(cpu, INTERRUPTIBILITY);
    uint64_t reason = enter(cpu, slice);
    uint64_t qualification = read_field(cpu, EXIT_QUAL);
    uint64_t handler_shadow = read_field(cpu, INTERRUPTIBILITY);
    uint64_t visits = read_reg(cpu, HV_X86_R11);
    bool entered_handler = port_exit(cpu, reason, HANDLER_PORT) &&
        read_reg(cpu, HV_X86_RIP) == HANDLER + 3 && visits == 1;
    uint64_t final_reason = reason;
    if (entered_handler) {
        field(cpu, ENTRY_EVENT, 0);
        reg(cpu, HV_X86_RIP, HANDLER + 5);
        final_reason = enter(cpu, slice);
    }
    bool continuation = final_reason == 12 && read_reg(cpu, HV_X86_RIP) == CODE + 12 &&
        read_reg(cpu, HV_X86_R10) == MARKER && read_reg(cpu, HV_X86_RFLAGS) == initial_flags;
    printf("{\"event\":\"%s\",\"pin_controls\":%" PRIu64
           ",\"staged_event\":%" PRIu64 ",\"prior_shadow\":%" PRIu64
           ",\"exit_reason\":%" PRIu64 ",\"exit_qualification\":%" PRIu64
           ",\"handler_shadow\":%" PRIu64 ",\"handler_visits\":%" PRIu64
           ",\"handler_reached\":%s,\"continuation\":%s,\"final_state\":",
           names[event], pins, staged, shadow, reason, qualification, handler_shadow, visits,
           entered_handler ? "true" : "false", continuation ? "true" : "false");
    snapshot(cpu);
    puts("}");
    check(hv_vcpu_destroy(cpu), "destroy vCPU");
    check(hv_vm_unmap(0, RAM), "unmap guest RAM");
    check(hv_vm_destroy(), "destroy VM");
    if (munmap(memory, RAM) != 0) return 1;
    if (staged != entry_event || shadow != 0) return 1;
    if (event == NONE) return continuation && visits == 0 ? 0 : 1;
    if (event == IRQ) return continuation && entered_handler ? 0 : 1;
    /* A negative NMI observation is also evidence if the controls passed. */
    return 0;
}
