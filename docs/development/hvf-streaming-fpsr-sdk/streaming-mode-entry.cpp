#include <Hypervisor/Hypervisor.h>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <initializer_list>
#include <libkern/OSCacheControl.h>
#include <sys/mman.h>

static void check(hv_return_t status, const char *operation) {
    if (status != HV_SUCCESS) {
        std::fprintf(stderr, "%s returned %#x\n", operation, status);
        std::exit(1);
    }
}

int main() {
    enum Mode { Normal, HostSetter, GuestSmstart };
    constexpr std::array modes{Normal, HostSetter, GuestSmstart};
    constexpr std::array mode_names{"normal", "host_sme_setter", "guest_smstart"};
    constexpr uint64_t fault_address = 0x09000000;
    for (Mode mode : modes) {
        for (bool query_sdk_mode : {false, true}) {
            check(hv_vm_create(nullptr), "create VM");
            auto *memory = static_cast<char *>(
                mmap(nullptr, 0x4000, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0));
            if (memory == MAP_FAILED)
                return 1;
            const uint32_t program[] = {
                mode == GuestSmstart ? 0xd503437fu : 0xd503201fu, // SMSTART SM or NOP
                0xd51b4423u,                                      // MSR FPSR,X3
                0xd53b4421u,                                      // MRS X1,FPSR
                0xd53b4244u,                                      // MRS X4,SVCR
                0xf9000041u,                                      // STR X1,[X2]
                0xd53b4421u,
                0xd53b4244u,
                0xf9000041u,
                0xd53b4421u,
                0xd53b4244u,
                0xf9000041u,
                0x14000000u,
            };
            std::memcpy(memory + 0x1000, program, sizeof(program));
            sys_icache_invalidate(memory + 0x1000, sizeof(program));
            check(hv_vm_map(memory, 0, 0x4000, HV_MEMORY_READ | HV_MEMORY_EXEC), "map code");
            hv_vcpu_t cpu;
            hv_vcpu_exit_t *exit_record;
            check(hv_vcpu_create(&cpu, &exit_record, nullptr), "create vCPU");
            check(hv_vcpu_set_reg(cpu, HV_REG_PC, 0x1000), "set PC");
            check(hv_vcpu_set_reg(cpu, HV_REG_CPSR, 0x3c5), "set EL1 PSTATE");
            check(hv_vcpu_set_reg(cpu, HV_REG_X2, fault_address), "set fault address");
            check(hv_vcpu_set_reg(cpu, HV_REG_X3, 1), "set guest FPSR source");
            check(hv_vcpu_set_sys_reg(cpu, HV_SYS_REG_CPACR_EL1,
                                      (3ull << 16) | (3ull << 20) | (3ull << 24)),
                  "enable SME, SVE and FP at EL1");
            if (mode == HostSetter) {
                hv_vcpu_sme_state_t streaming{};
                streaming.streaming_sve_mode_enabled = true;
                check(hv_vcpu_set_sme_state(cpu, &streaming), "start streaming through SDK");
            }
            for (unsigned phase = 0; phase < 3; ++phase) {
                if (phase == 2)
                    check(hv_vcpu_set_reg(cpu, HV_REG_FPSR, 4), "host FPSR update");
                check(hv_vcpu_run(cpu), "guest run");
                uint64_t fpsr = 0, svcr = 0, pc = 0;
                check(hv_vcpu_get_reg(cpu, HV_REG_X1, &fpsr), "guest FPSR result");
                check(hv_vcpu_get_reg(cpu, HV_REG_X4, &svcr), "guest SVCR result");
                check(hv_vcpu_get_reg(cpu, HV_REG_PC, &pc), "guest exit PC");
                int sdk_sm = -1;
                if (query_sdk_mode) {
                    hv_vcpu_sme_state_t observed{};
                    check(hv_vcpu_get_sme_state(cpu, &observed), "SDK mode read");
                    sdk_sm = observed.streaming_sve_mode_enabled;
                }
                std::printf("%s phase=%u fpsr=0x%llx svcr=0x%llx sdk_sm=%d "
                            "pc=0x%llx exit=%u syndrome=0x%llx ipa=0x%llx\n",
                            mode_names[mode], phase, fpsr, svcr, sdk_sm, pc,
                            unsigned(exit_record->reason), exit_record->exception.syndrome,
                            exit_record->exception.physical_address);
                std::fflush(stdout);
                if (exit_record->reason != HV_EXIT_REASON_EXCEPTION ||
                    (exit_record->exception.syndrome >> 26) != 0x24 ||
                    exit_record->exception.physical_address != fault_address ||
                    pc != 0x1010 + 12 * phase)
                    return 2;
                if (svcr != (mode != Normal) || (query_sdk_mode && sdk_sm != (mode != Normal)))
                    return 3;
                check(hv_vcpu_set_reg(cpu, HV_REG_PC, pc + 4), "skip deliberate data abort");
            }
            check(hv_vcpu_destroy(cpu), "destroy vCPU");
            check(hv_vm_unmap(0, 0x4000), "unmap");
            check(hv_vm_destroy(), "destroy VM");
            if (munmap(memory, 0x4000) != 0)
                return 4;
        }
    }
}
