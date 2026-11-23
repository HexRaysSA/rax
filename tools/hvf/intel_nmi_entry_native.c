/* SDK-only control for VM-entry event admission. No RAX library is linked. */
#define RAX_RAM_ENTRY_NO_MAIN
#include "intel_ram_entry_native.c"

enum {
    PIN_CONTROLS = 0x4000, ENTRY_EVENT = 0x4016, EXIT_QUAL = 0x6400,
    IDT_BASE = 0x6818, IDT_LIMIT = 0x4812, INTERRUPTIBILITY = 0x4824,
    IDT_VECTORING_INFO = 0x4408, EXIT_GUEST_PHYSICAL = 0x2400,
    IDT = 0xc000, HANDLER = 0xb000, IRQ_VECTOR = 0x40,
    IDT_PAGE_SIZE = 0x1000, EXIT_EPT_VIOLATION = 48,
    EXIT_INSTRUCTION_LENGTH = 0x440c, EXIT_CONTROL_REGISTER = 28,
    START_PORT = 0x81, HANDLER_PORT = 0x80,
};

enum event { NONE, IRQ, NMI, NMI_WITH_IF, NMI_WITHOUT_VIRTUAL_BLOCKING, IRQ_VECTORING, CR0_NE };
static const char *const names[] = {
    "none", "irq", "nmi", "nmi-with-if", "nmi-without-virtual-blocking", "irq-vectoring",
    "cr0-ne",
};

/* MOV from CR0; save it in R12; clear NE; MOV to CR0; read into R13;
 * set NE; MOV to CR0; read into R14; HLT. RAX supplies both proposed writes.
 */
static const uint8_t cr0_guest[] = {
    0x0f, 0x20, 0xc0, 0x49, 0x89, 0xc4, 0x48, 0x0f, 0xba, 0xf0, 0x05,
    0x0f, 0x22, 0xc0, 0x41, 0x0f, 0x20, 0xc5, 0x48, 0x0f, 0xba, 0xe8, 0x05,
    0x0f, 0x22, 0xc0, 0x41, 0x0f, 0x20, 0xc6, 0xf4,
};

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

static int observe_irq_vectoring(hv_vcpuid_t cpu, uint8_t *memory, uint64_t slice)
{
    const uint64_t irq = UINT64_C(0x80000000) | IRQ_VECTOR;
    uint64_t pc = read_reg(cpu, HV_X86_RIP), sp = read_reg(cpu, HV_X86_RSP);
    check(hv_vm_unmap(IDT, IDT_PAGE_SIZE), "unmap the interrupt gate");
    field(cpu, ENTRY_EVENT, irq);
    uint64_t reason = enter(cpu, slice);
    uint64_t qualification = 0, gpa = 0, vectoring = 0;
    if (reason == EXIT_EPT_VIOLATION) {
        qualification = read_field(cpu, EXIT_QUAL);
        gpa = read_field(cpu, EXIT_GUEST_PHYSICAL);
        vectoring = read_field(cpu, IDT_VECTORING_INFO);
    }
    uint64_t stopped_pc = read_reg(cpu, HV_X86_RIP);
    uint64_t stopped_sp = read_reg(cpu, HV_X86_RSP);
    uint64_t stopped_visits = read_reg(cpu, HV_X86_R11);
    check(hv_vm_map(memory + IDT, IDT, IDT_PAGE_SIZE,
                    HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC), "remap the interrupt gate");

    // SDM 29.2.4 leaves bit 12 of valid IDT-vectoring information undefined.
    // It is reserved in the VM-entry event field and must be zero there.
    uint64_t replay = vectoring & ~(UINT64_C(1) << 12);
    bool interrupted = reason == EXIT_EPT_VIOLATION && (qualification & 7) == 1 &&
        gpa >= IDT + 16 * IRQ_VECTOR && gpa < IDT + 16 * (IRQ_VECTOR + 1) &&
        replay == irq && stopped_pc == pc && stopped_sp == sp && stopped_visits == 0;
    uint64_t next = reason, final = reason;
    bool reached = false, continued = false;
    if (interrupted) {
        // The selected external interrupt has no error code or instruction length.
        field(cpu, ENTRY_EVENT, replay);
        next = enter(cpu, slice);
        if (port_exit(cpu, next, HANDLER_PORT) && read_reg(cpu, HV_X86_RIP) == HANDLER + 3 &&
            read_reg(cpu, HV_X86_R11) == 1) {
            reached = true;
            field(cpu, ENTRY_EVENT, 0);
            reg(cpu, HV_X86_RIP, HANDLER + 5);
            final = enter(cpu, slice);
            continued = final == 12 && read_reg(cpu, HV_X86_RIP) == CODE + 12 &&
                read_reg(cpu, HV_X86_RSP) == sp && read_reg(cpu, HV_X86_R10) == MARKER &&
                read_reg(cpu, HV_X86_RFLAGS) == 0x202 && read_reg(cpu, HV_X86_R11) == 1;
        }
    }
    printf("{\"event\":\"irq-vectoring\",\"exit_reason\":%" PRIu64
           ",\"exit_qualification\":%" PRIu64 ",\"guest_physical\":%" PRIu64
           ",\"idt_vectoring\":%" PRIu64 ",\"stopped_pc\":%" PRIu64
           ",\"stopped_sp\":%" PRIu64 ",\"stopped_visits\":%" PRIu64
           ",\"handler_exit\":%" PRIu64 ",\"final_exit\":%" PRIu64
           ",\"interrupted\":%s,\"handler_reached\":%s,\"continuation\":%s}\n",
           reason, qualification, gpa, vectoring, stopped_pc, stopped_sp, stopped_visits,
           next, final, interrupted ? "true" : "false", reached ? "true" : "false",
           continued ? "true" : "false");
    return interrupted && reached && continued ? 0 : 1;
}

static int observe_cr0_ne(hv_vcpuid_t cpu, uint64_t slice)
{
    const uint64_t ne = UINT64_C(1) << 5;
    const uint64_t original = read_field(cpu, G_CR0);
    const uint64_t mask = read_field(cpu, CR0_MASK);
    const uint64_t shadow = read_field(cpu, CR0_SHADOW);
    const uint64_t start = read_reg(cpu, HV_X86_RIP);
    const uint64_t offsets[] = {11, 23};
    const uint64_t requested[] = {original & ~ne, original};
    printf("{\"event\":\"cr0-ne\",\"mask\":%" PRIu64 ",\"backing\":%" PRIu64
           ",\"shadow\":%" PRIu64 ",\"writes\":[", mask, original, shadow);
    // The SDK can add its own masks on entry. The guest changes only NE,
    // and full initial shadow agreement keeps the other bits out of scope.
    bool accepted = (mask & ne) != 0 && shadow == original && (original & ne) != 0;
    unsigned published = 0;
    for (size_t i = 0; accepted && i < sizeof(offsets) / sizeof(offsets[0]); i++) {
        uint64_t reason = enter(cpu, slice);
        uint64_t rip = read_reg(cpu, HV_X86_RIP);
        uint64_t value = read_reg(cpu, HV_X86_RAX);
        uint64_t backing = read_field(cpu, G_CR0);
        uint64_t prior_shadow = read_field(cpu, CR0_SHADOW);
        uint64_t register_cr0 = read_reg(cpu, HV_X86_CR0);
        uint64_t qualification = 0, length = 0;
        if (reason == EXIT_CONTROL_REGISTER) {
            qualification = read_field(cpu, EXIT_QUAL);
            length = read_field(cpu, EXIT_INSTRUCTION_LENGTH);
        }
        accepted = reason == EXIT_CONTROL_REGISTER && rip == start + offsets[i] &&
            qualification == 0 && length == 3 && value == requested[i] &&
            backing == original && prior_shadow == (i == 0 ? shadow : requested[0]);
        printf("%s{\"reason\":%" PRIu64 ",\"rip\":%" PRIu64 ",\"operand\":%" PRIu64
               ",\"qualification\":%" PRIu64 ",\"length\":%" PRIu64 ",\"backing\":%" PRIu64
               ",\"prior_shadow\":%" PRIu64 ",\"register_cr0\":%" PRIu64 ",\"shadow_write\":",
               i ? "," : "", reason, rip, value, qualification, length, backing,
               prior_shadow, register_cr0);
        if (accepted) {
            // VMX retains its fixed backing bit. The client only publishes
            // the guest-owned value in the read shadow for this one-bit move.
            hv_return_t status = hv_vmx_vcpu_write_vmcs(cpu, CR0_SHADOW, value);
            printf("%u", (uint32_t)status);
            accepted = status == HV_SUCCESS && read_field(cpu, CR0_SHADOW) == value &&
                read_field(cpu, G_CR0) == original;
            if (accepted) {
                reg(cpu, HV_X86_RIP, rip + length);
                published++;
            }
        } else {
            printf("null");
        }
        printf("}");
    }
    uint64_t reason = accepted ? enter(cpu, slice) : 0;
    uint64_t rip = read_reg(cpu, HV_X86_RIP);
    uint64_t first = read_reg(cpu, HV_X86_R12);
    uint64_t cleared = read_reg(cpu, HV_X86_R13);
    uint64_t restored = read_reg(cpu, HV_X86_R14);
    uint64_t backing = read_field(cpu, G_CR0);
    uint64_t final_shadow = read_field(cpu, CR0_SHADOW);
    bool continued = accepted && reason == 12 && rip == start + sizeof(cr0_guest) - 1 &&
        first == original && cleared == requested[0] && restored == original &&
        backing == original && final_shadow == shadow;
    printf("],\"published\":%u,\"final_reason\":%" PRIu64 ",\"final_rip\":%" PRIu64
           ",\"guest_initial\":%" PRIu64 ",\"guest_cleared\":%" PRIu64
           ",\"guest_restored\":%" PRIu64 ",\"final_backing\":%" PRIu64
           ",\"final_shadow\":%" PRIu64 ",\"continuation\":%s}\n",
           published, reason, rip, first, cleared, restored, backing, final_shadow,
           continued ? "true" : "false");
    /* A rejected read shadow, missing intercept, or wrong guest value is a
     * recorded negative observation if the baseline port marker completed.
     */
    return 0;
}

static void destroy(hv_vcpuid_t cpu, void *memory)
{
    check(hv_vcpu_destroy(cpu), "destroy vCPU");
    check(hv_vm_unmap(0, RAM), "unmap guest RAM");
    check(hv_vm_destroy(), "destroy VM");
    if (munmap(memory, RAM) != 0) {
        perror("unmap host RAM");
        exit(1);
    }
}

int main(int argc, char **argv)
{
    if (argc != 2) return 2;
    const size_t count = sizeof(names) / sizeof(names[0]);
    size_t event = 0;
    while (event < count && strcmp(argv[1], names[event]) != 0) event++;
    if (event == count) return 2;

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
    if (event == CR0_NE) memcpy(memory + CODE + sizeof(marker), cr0_guest, sizeof(cr0_guest));
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
    const uint64_t virtual_nmis = UINT64_C(1) << 5;
    uint64_t pins = read_field(cpu, PIN_CONTROLS) | 1 | (1 << 3);
    if (event == NMI_WITHOUT_VIRTUAL_BLOCKING) pins &= ~virtual_nmis;
    else pins |= virtual_nmis;
    if (event == NMI_WITHOUT_VIRTUAL_BLOCKING && ((uint32_t)caps & virtual_nmis) != 0) {
        printf("{\"event\":\"%s\",\"admission\":\"virtual-blocking-required\","
               "\"pin_capability\":%" PRIu64 ",\"requested_pin_controls\":%" PRIu64 ","
               "\"guest_entry_attempted\":false}\n",
               names[event], caps, pins);
        destroy(cpu, memory);
        return 0;
    }
    if ((pins & ~(caps >> 32)) != 0 || ((uint32_t)caps & ~pins) != 0) {
        fprintf(stderr, "requested NMI pin controls unavailable\n");
        return 1;
    }
    field(cpu, PIN_CONTROLS, pins);
    const uint64_t initial_flags =
        event == IRQ || event == NMI_WITH_IF || event == IRQ_VECTORING ? 0x202 : 2;
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
    if (event == IRQ_VECTORING) {
        int result = observe_irq_vectoring(cpu, memory, slice);
        destroy(cpu, memory);
        return result;
    }
    if (event == CR0_NE) {
        int result = observe_cr0_ne(cpu, slice);
        destroy(cpu, memory);
        return result;
    }

    uint64_t entry_event = 0;
    if (event == IRQ) entry_event = UINT64_C(0x80000000) | IRQ_VECTOR;
    if (event >= NMI) entry_event = UINT64_C(0x80000202);
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
    printf("{\"event\":\"%s\",\"pin_controls\":%" PRIu64 ",\"pin_capability\":%" PRIu64
           ",\"staged_event\":%" PRIu64 ",\"prior_shadow\":%" PRIu64
           ",\"exit_reason\":%" PRIu64 ",\"exit_qualification\":%" PRIu64
           ",\"handler_shadow\":%" PRIu64 ",\"handler_visits\":%" PRIu64
           ",\"handler_reached\":%s,\"continuation\":%s,\"final_state\":",
           names[event], pins, caps, staged, shadow, reason, qualification, handler_shadow, visits,
           entered_handler ? "true" : "false", continuation ? "true" : "false");
    snapshot(cpu);
    puts("}");
    destroy(cpu, memory);
    if (staged != entry_event || shadow != 0) return 1;
    if (event == NONE) return continuation && visits == 0 ? 0 : 1;
    if (event == IRQ) return continuation && entered_handler ? 0 : 1;
    /* A negative NMI observation is also evidence if the controls passed. */
    return 0;
}
