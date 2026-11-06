#include <Hypervisor/Hypervisor.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <initializer_list>
#include <libkern/OSCacheControl.h>
#include <sys/mman.h>
#include <vector>
static void check(hv_return_t status, const char *label) {
    if (status != HV_SUCCESS) {
        std::fprintf(stderr, "%s status=0x%x\n", label, status);
        std::exit(1);
    }
}
int main() {
    size_t svl = 0;
    check(hv_sme_config_get_max_svl_bytes(&svl), "maximum SVL");
    for (unsigned touch = 0; touch < 5; touch++) {
        for (bool za : {false, true}) {
            for (bool stream : {false, true}) {
                for (bool getter : {false, true}) {
                    check(hv_vm_create(nullptr), "VM");
                    void *memory = mmap(nullptr, 0x4000, PROT_READ | PROT_WRITE,
                                        MAP_ANON | MAP_PRIVATE, -1, 0);
                    if (memory == MAP_FAILED) {
                        return 1;
                    }
                    const uint32_t words[] = {0xd53b4421, 0xf9000041, 0xd51b4423, 0xd53b4421,
                                              0xf9000041, 0xd53b4421, 0xf9000041, 0xd53b4421,
                                              0xf9000041, 0xd53b4421, 0xf9000041, 0x14000000};
                    std::memcpy(static_cast<char *>(memory) + 0x1000, words, sizeof(words));
                    sys_icache_invalidate(static_cast<char *>(memory) + 0x1000, sizeof(words));
                    check(hv_vm_map(memory, 0, 0x4000,
                                    HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC),
                          "map");
                    hv_vcpu_t cpu;
                    hv_vcpu_exit_t *exit;
                    check(hv_vcpu_create(&cpu, &exit, nullptr), "CPU");
                    check(hv_vcpu_set_reg(cpu, HV_REG_PC, 0x1000), "PC");
                    check(hv_vcpu_set_reg(cpu, HV_REG_CPSR, 0x3c5), "CPSR");
                    check(hv_vcpu_set_reg(cpu, HV_REG_X2, 0x09000000), "X2");
                    check(hv_vcpu_set_reg(cpu, HV_REG_X3, 1), "X3");
                    check(hv_vcpu_set_sys_reg(cpu, HV_SYS_REG_CPACR_EL1,
                                              (3ull << 16) | (3ull << 20) | (3ull << 24)),
                          "CPACR");
                    hv_vcpu_sme_state_t mode = {stream, za};
                    check(hv_vcpu_set_sme_state(cpu, &mode), "SME");
                    check(hv_vcpu_set_reg(cpu, HV_REG_FPSR, 1), "initial FPSR");
                    for (unsigned phase = 0; phase < 5; ++phase) {
                        if (phase == 3) {
                            check(hv_vcpu_set_reg(cpu, HV_REG_FPSR, 2), "reentry FPSR");
                        }
                        if (phase == 4) {
                            check(hv_vcpu_set_sme_state(cpu, &mode), "same SME");
                            check(hv_vcpu_set_reg(cpu, HV_REG_FPSR, 4), "same SME FPSR");
                        }
                        if (stream) {
                            std::vector<uint8_t> z(svl), p(svl / 8);
                            if (touch == 1 || touch == 2 || touch == 4) {
                                check(hv_vcpu_get_sme_z_reg(cpu, static_cast<hv_sme_z_reg_t>(0),
                                                            z.data(), z.size()),
                                      "get Z0");
                            }
                            if (touch == 2 || touch == 4) {
                                check(hv_vcpu_set_sme_z_reg(cpu, static_cast<hv_sme_z_reg_t>(0),
                                                            z.data(), z.size()),
                                      "set Z0");
                            }
                            if (touch == 3 || touch == 4) {
                                check(hv_vcpu_get_sme_p_reg(cpu, static_cast<hv_sme_p_reg_t>(0),
                                                            p.data(), p.size()),
                                      "get P0");
                                check(hv_vcpu_set_sme_p_reg(cpu, static_cast<hv_sme_p_reg_t>(0),
                                                            p.data(), p.size()),
                                      "set P0");
                            }
                        }
                        uint64_t requested = phase == 3 ? 2 : phase == 4 ? 4 : 1;
                        check(hv_vcpu_set_reg(cpu, HV_REG_FPSR, requested), "last FPSR");
                        uint64_t before = 0;
                        if (getter) {
                            check(hv_vcpu_get_reg(cpu, HV_REG_FPSR, &before), "read before");
                        }
                        check(hv_vcpu_run(cpu), "run");
                        uint64_t guest = 0, pc = 0;
                        check(hv_vcpu_get_reg(cpu, HV_REG_X1, &guest), "guest");
                        check(hv_vcpu_get_reg(cpu, HV_REG_PC, &pc), "exit PC");
                        uint64_t saved_guest = 0;
                        check(hv_vcpu_get_reg(cpu, HV_REG_FPSR, &saved_guest), "saved FPSR");
                        std::printf("{\"touch\":%u,\"za\":%d,\"stream\":%d,\"getter\":%d,\"phase\":"
                                    "%u,\"requested\":%llu,\"before\":%llu,\"guest\":%llu,\"saved_"
                                    "guest\":%llu,\"pc\":%llu,\"reason\":%u,\"syndrome\":%llu}\n",
                                    touch, za, stream, getter, phase, requested, before, guest,
                                    saved_guest, pc, unsigned(exit->reason),
                                    exit->exception.syndrome);
                        std::fflush(stdout);
                        if (exit->reason != HV_EXIT_REASON_EXCEPTION ||
                            (exit->exception.syndrome >> 26) != 0x24) {
                            return 2;
                        }
                        check(hv_vcpu_set_reg(cpu, HV_REG_PC, pc + 4), "advance");
                    }
                    check(hv_vcpu_destroy(cpu), "destroy CPU");
                    check(hv_vm_destroy(), "destroy VM");
                    munmap(memory, 0x4000);
                }
            }
        }
    }
}
