/* SDK-only control for the RAM guest used by intel_mmio_native_guest.rs.
 * Each invocation owns a fresh VM; no RAX library is linked. This is an
 * observation matrix, not a substitute for native RAX execution qualification.
 */
#define main availability_main
#include "native_intel_availability.c"
#undef main
#include <Hypervisor/hv_vmx.h>
#include <inttypes.h>
#include <mach/mach_time.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/mman.h>

#define RAM UINT64_C(0x200000)
#define CODE UINT64_C(0x10000)
#define MARKER UINT64_C(0xa1b2c3d4e5f60718)
#define CR0 UINT64_C(0x80010033)
#define CR4 UINT64_C(0x220)

/* Intel VMCS encodings: SDM Vol. 3, Appendix B. The SDK accepts field IDs. */
enum {
    G_CR0 = 0x6800, G_CR3 = 0x6802, G_CR4 = 0x6804, G_EFER = 0x2806,
    CR0_MASK = 0x6000, CR4_MASK = 0x6002,
    CR0_SHADOW = 0x6004, CR4_SHADOW = 0x6006,
    ENTRY = 0x4012, EXIT_REASON = 0x4402,
};

struct variant {
    const char *name;
    bool full_shadows, required_masks, required_state, register_api, vmxe_mask;
};
static const struct variant variants[] = {
    {"baseline", false, false, false, false, false},
    {"full-shadows", true, false, false, false, false},
    {"required-masks", false, true, false, false, false},
    {"required-masks-and-shadows", true, true, false, false, false},
    {"register-controls", false, false, false, true, false},
    {"register-controls-and-shadows", true, false, false, true, false},
    {"required-state-and-shadows", true, true, true, false, false},
    {"vmx-masks-and-shadows", true, true, true, false, true},
};

static void check(hv_return_t status, const char *operation)
{
    if (status != HV_SUCCESS) {
        fprintf(stderr, "%s: SDK status %u\n", operation, (uint32_t)status);
        exit(1); /* The OS releases this process's owned VM and mappings. */
    }
}

static void field(hv_vcpuid_t cpu, uint32_t id, uint64_t value)
{
    check(hv_vmx_vcpu_write_vmcs(cpu, id, value), "write VMCS field");
}

static uint64_t read_field(hv_vcpuid_t cpu, uint32_t id)
{
    uint64_t value = 0;
    check(hv_vmx_vcpu_read_vmcs(cpu, id, &value), "read VMCS field");
    return value;
}

static void reg(hv_vcpuid_t cpu, hv_x86_reg_t id, uint64_t value)
{
    check(hv_vcpu_write_register(cpu, id, value), "write register");
}

static uint64_t read_reg(hv_vcpuid_t cpu, hv_x86_reg_t id)
{
    uint64_t value = 0;
    check(hv_vcpu_read_register(cpu, id, &value), "read register");
    return value;
}

static uint64_t required(hv_vcpuid_t cpu, uint32_t id)
{
    uint64_t must_one = 0, may_one = 0;
    check(hv_vmx_vcpu_get_cap_write_vmcs(cpu, id, &must_one, &may_one),
          "get field write constraints");
    if ((must_one & ~may_one) != 0) {
        fprintf(stderr, "inconsistent field constraints\n");
        exit(1);
    }
    return must_one;
}

static void controls(hv_vcpuid_t cpu)
{
    const struct { hv_vmx_capability_t cap; uint32_t id; uint64_t request; } banks[] = {
        {HV_VMX_CAP_PINBASED, 0x4000, 0},
        {HV_VMX_CAP_PROCBASED, 0x4002,
         (1u << 3) | (1u << 7) | (1u << 19) | (1u << 20) | (1u << 24) | (1u << 31)},
        {HV_VMX_CAP_PROCBASED2, 0x401e, (1u << 1) | (1u << 3) | (1u << 7)},
        {HV_VMX_CAP_ENTRY, ENTRY, (1u << 9) | (1u << 15)},
    };
    for (size_t i = 0; i < sizeof(banks) / sizeof(banks[0]); i++) {
        uint64_t capability = 0;
        check(hv_vmx_read_capability(banks[i].cap, &capability), "read VMX capability");
        uint64_t must_one = (uint32_t)capability, may_one = capability >> 32;
        if (((must_one | banks[i].request) & ~may_one) != 0) {
            fprintf(stderr, "unsupported requested controls\n");
            exit(1);
        }
        field(cpu, banks[i].id, must_one | banks[i].request);
    }
    field(cpu, 0x4004, 0); /* Exception bitmap. */
}

static void word(uint8_t *memory, uint64_t address, uint64_t value)
{
    if (address > RAM - sizeof(value)) {
        abort();
    }
    memcpy(memory + address, &value, sizeof(value));
}

static void populate(uint8_t *memory)
{
    word(memory, 0x1000, 0x2003);
    for (uint64_t gigabyte = 0; gigabyte < 2; gigabyte++) {
        uint64_t directory = 0x3000 + gigabyte * 0x1000;
        word(memory, 0x2000 + gigabyte * 8, directory | 3);
        for (uint64_t page = 0; page < 512; page++) {
            word(memory, directory + page * 8,
                 (gigabyte << 30) | (page << 21) | 0x83);
        }
    }
    word(memory, 0x9008, UINT64_C(0x00af9b000000ffff));
    word(memory, 0x9010, UINT64_C(0x00cf93000000ffff));
    word(memory, 0x9018, UINT64_C(0x00008b0080000067));
    word(memory, 0x8004, RAM - 0x1000);
    uint16_t iomap = 0x68;
    memcpy(memory + 0x8066, &iomap, sizeof(iomap));
    memory[CODE] = 0x49;
    memory[CODE + 1] = 0xba; /* MOV R10, imm64; HLT. */
    word(memory, CODE + 2, MARKER);
    memory[CODE + 10] = 0xf4;
}

static void setup(hv_vcpuid_t cpu, const struct variant *v)
{
    controls(cpu);
    uint64_t cr0_mask = 0x20, cr4_mask = 0;
    if (v->required_masks) {
        cr0_mask |= required(cpu, CR0_MASK);
        cr4_mask |= required(cpu, CR4_MASK);
    }
    if (v->vmxe_mask) {
        cr4_mask |= UINT64_C(1) << 13;
    }
    field(cpu, CR0_MASK, cr0_mask);
    field(cpu, CR4_MASK, cr4_mask);
    field(cpu, CR0_SHADOW, v->full_shadows ? CR0 : 0x20);
    field(cpu, CR4_SHADOW, v->full_shadows ? CR4 : 0);

    /* ES, CS, SS, DS, FS, GS, LDTR, TR: identical to the Rust RAM fixture. */
    for (uint32_t i = 0; i < 8; i++) {
        uint64_t selector = i == 1 ? 8 : 16;
        uint64_t base = 0, limit = UINT32_MAX, access = 0xc093;
        if (i == 1) access = 0xa09b;
        if (i == 6) { selector = 0; limit = 0; access = 0x10000; }
        if (i == 7) { selector = 24; base = 0x8000; limit = 0x67; access = 0x8b; }
        field(cpu, 0x800 + 2 * i, selector);
        field(cpu, 0x6806 + 2 * i, base);
        field(cpu, 0x4800 + 2 * i, limit);
        field(cpu, 0x4814 + 2 * i, access);
    }
    field(cpu, 0x6816, 0x9000); /* GDTR base. */
    field(cpu, 0x4810, 47);
    field(cpu, 0x6818, 0); /* IDTR base. */
    field(cpu, 0x4812, 0);
    uint64_t cr0 = CR0, cr4 = CR4;
    if (v->required_state) {
        cr0 |= required(cpu, G_CR0);
        cr4 |= required(cpu, G_CR4);
    }
    if (v->vmxe_mask) cr4 |= UINT64_C(1) << 13;
    if (v->register_api) {
        reg(cpu, HV_X86_CR0, cr0);
        reg(cpu, HV_X86_CR4, cr4);
    } else {
        field(cpu, G_CR0, cr0);
        field(cpu, G_CR4, cr4);
    }
    field(cpu, G_CR3, 0x1000);
    reg(cpu, HV_X86_CR2, 0);
    reg(cpu, HV_X86_TPR, 0);
    field(cpu, G_EFER, 0x500);
    reg(cpu, HV_X86_DR0, 0);
    reg(cpu, HV_X86_DR1, 0);
    reg(cpu, HV_X86_DR2, 0);
    reg(cpu, HV_X86_DR3, 0);
    reg(cpu, HV_X86_DR6, 0xffff0ff0);
    field(cpu, 0x681a, 0x400);
    reg(cpu, HV_X86_XCR0, 1);
    reg(cpu, HV_X86_RAX, UINT64_C(0x1122334455667788));
    reg(cpu, HV_X86_RDI, 0x40000080);
    reg(cpu, HV_X86_R10, 0);
    reg(cpu, HV_X86_RSP, RAM - 0x1000);
    reg(cpu, HV_X86_RIP, CODE);
    reg(cpu, HV_X86_RFLAGS, 2);
}

static void snapshot(hv_vcpuid_t cpu)
{
    const struct { const char *name; uint32_t id; } fields[] = {
        {"cr0", G_CR0}, {"cr3", G_CR3}, {"cr4", G_CR4}, {"efer", G_EFER},
        {"cr0_mask", CR0_MASK}, {"cr4_mask", CR4_MASK},
        {"cr0_shadow", CR0_SHADOW}, {"cr4_shadow", CR4_SHADOW},
        {"entry_controls", ENTRY}, {"cs_access", 0x4816},
        {"activity", 0x4826}, {"interruptibility", 0x4824},
    };
    printf("{");
    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
        printf("%s\"%s\":%" PRIu64, i ? "," : "", fields[i].name,
               read_field(cpu, fields[i].id));
    }
    printf(",\"rip\":%" PRIu64 ",\"r10\":%" PRIu64 ",\"rax\":%" PRIu64
           ",\"rdi\":%" PRIu64 ",\"rflags\":%" PRIu64 "}",
           read_reg(cpu, HV_X86_RIP), read_reg(cpu, HV_X86_R10),
           read_reg(cpu, HV_X86_RAX), read_reg(cpu, HV_X86_RDI),
           read_reg(cpu, HV_X86_RFLAGS));
}

int main(int argc, char **argv)
{
    const struct variant *v = NULL;
    for (size_t i = 0; i < sizeof(variants) / sizeof(variants[0]); i++) {
        if (argc == 2 && strcmp(argv[1], variants[i].name) == 0) v = &variants[i];
    }
    if (v == NULL) return 2;
    int preflight = availability_main();
    if (preflight != 0) return preflight;
    check(hv_vm_create(HV_VM_DEFAULT), "create VM");
    uint8_t *memory = mmap(NULL, RAM, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANON, -1, 0);
    if (memory == MAP_FAILED) return 1;
    populate(memory);
    check(hv_vm_map(memory, 0, RAM, HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC),
          "map guest RAM");
    hv_vcpuid_t cpu;
    check(hv_vcpu_create(&cpu, HV_VCPU_DEFAULT), "create CPU");
    setup(cpu, v);
    printf("{\"probe\":\"ram-entry\",\"variant\":\"%s\",\"before\":", v->name);
    snapshot(cpu);
    fflush(stdout);
    mach_timebase_info_data_t timebase;
    if (mach_timebase_info(&timebase) != KERN_SUCCESS || timebase.numer == 0) return 1;
    /* 100 ms per call, at most ten calls; Python also bounds the owned process. */
    uint64_t ticks = UINT64_C(100000000) * timebase.denom / timebase.numer;
    hv_return_t status = HV_SUCCESS;
    uint64_t reason = 0;
    size_t entries = 0;
    do {
        uint64_t now = mach_absolute_time();
        if (ticks > UINT64_MAX - now) return 1;
        status = hv_vcpu_run_until(cpu, now + ticks);
        entries++;
        if (status != HV_SUCCESS) break;
        reason = read_field(cpu, EXIT_REASON);
    } while (reason == 52 && entries < 10); /* SDK deadline, not guest HLT. */
    bool halted = status == HV_SUCCESS && reason == 12 &&
        read_reg(cpu, HV_X86_RIP) == CODE + 10 &&
        read_reg(cpu, HV_X86_R10) == MARKER &&
        read_reg(cpu, HV_X86_RAX) == UINT64_C(0x1122334455667788) &&
        read_reg(cpu, HV_X86_RDI) == 0x40000080 && read_reg(cpu, HV_X86_RFLAGS) == 2;
    printf(",\"after\":");
    snapshot(cpu);
    printf(",\"run_status\":%u,\"exit_reason\":", (uint32_t)status);
    if (status == HV_SUCCESS) printf("%" PRIu64, reason); else printf("null");
    printf(",\"entries\":%zu,\"guest_entry_attempted\":true,\"guest_reached_hlt\":%s",
           entries, halted ? "true" : "false");
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
