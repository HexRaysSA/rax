// Observe the SDK interface without running guest instructions or writing VMCS.
#define main availability_main
#include "native_intel_availability.c"
#undef main
#include <Hypervisor/hv_vmx.h>
#include "probe_fields.h"

int main(void)
{
    int preflight = availability_main();
    if (preflight != 0) {
        return preflight;
    }
    hv_return_t vm_status = hv_vm_create(HV_VM_DEFAULT);
    if (vm_status != HV_SUCCESS) {
        printf("{\"probe\":\"vmcs\",\"vm_create_status\":%u,"
               "\"guest_execution_performed\":false}\n", (uint32_t)vm_status);
        return 4;
    }
    hv_vcpuid_t cpu = 0;
    hv_return_t cpu_status = hv_vcpu_create(&cpu, HV_VCPU_DEFAULT);
    printf("{\"probe\":\"vmcs\",\"vm_create_status\":0,"
           "\"vcpu_create_status\":%u,\"fields\":[", (uint32_t)cpu_status);
    size_t count = 0;
    if (cpu_status == HV_SUCCESS) {
        for (size_t index = 0; index < sizeof(probe_fields) / sizeof(probe_fields[0]); index++) {
            uint64_t value = 0, allowed_0 = 0, allowed_1 = 0;
            uint32_t id = probe_fields[index].id;
            hv_return_t read_status = hv_vmx_vcpu_read_vmcs(cpu, id, &value);
            hv_return_t cap_status = hv_vmx_vcpu_get_cap_write_vmcs(cpu, id, &allowed_0, &allowed_1);
            printf("%s{\"name\":\"%s\",\"id\":%u,\"read_status\":%u,"
                   "\"write_cap_status\":%u,\"value\":", index ? "," : "",
                   probe_fields[index].name, id, (uint32_t)read_status, (uint32_t)cap_status);
            if (read_status == HV_SUCCESS) {
                printf("%llu", (unsigned long long)value);
            } else {
                printf("null");
            }
            printf(",\"required_one\":");
            if (cap_status == HV_SUCCESS) {
                printf("%llu,\"allowed_one\":%llu", (unsigned long long)allowed_0,
                       (unsigned long long)allowed_1);
            } else {
                printf("null,\"allowed_one\":null");
            }
            printf("}");
            count++;
        }
    }
    printf("],\"field_count\":%zu,\"vcpu_destroy_status\":", count);
    hv_return_t cpu_destroy = HV_SUCCESS;
    if (cpu_status == HV_SUCCESS) {
        cpu_destroy = hv_vcpu_destroy(cpu);
        printf("%u", (uint32_t)cpu_destroy);
    } else {
        printf("null");
    }
    hv_return_t vm_destroy = hv_vm_destroy();
    printf(",\"vm_destroy_status\":%u,\"guest_execution_performed\":false}\n",
           (uint32_t)vm_destroy);
    return cpu_status == HV_SUCCESS && cpu_destroy == HV_SUCCESS && vm_destroy == HV_SUCCESS ? 0 : 5;
}
