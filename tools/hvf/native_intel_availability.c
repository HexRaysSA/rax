// SDK-only capability observation. No RAX engine or guest instruction runs.
#if !defined(__APPLE__) || !defined(__x86_64__)
#error This probe requires the Intel macOS SDK target.
#endif
#include <Hypervisor/hv.h>
#include <cpuid.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/sysctl.h>

static int integer_property(const char *name, int *error)
{
    int value = -1;
    size_t length = sizeof(value);
    if (sysctlbyname(name, &value, &length, NULL, 0) != 0) {
        *error = errno;
        return -1;
    }
    if (length != sizeof(value)) {
        *error = EINVAL;
        return -1;
    }
    *error = 0;
    return value;
}

int main(void)
{
    unsigned eax = 0, ebx = 0, ecx = 0, edx = 0;
    char vendor[13] = {0};
    int cpuid_present = __get_cpuid(0, &eax, &ebx, &ecx, &edx);
    memcpy(vendor, &ebx, 4);
    memcpy(vendor + 4, &edx, 4);
    memcpy(vendor + 8, &ecx, 4);
    int genuine_intel = cpuid_present && memcmp(vendor, "GenuineIntel", 12) == 0;
    int translated_error = 0, support_error = 0, guest_error = 0;
    int translated = integer_property("sysctl.proc_translated", &translated_error);
    // This property is absent for native processes on older Intel macOS.
    if (translated_error == ENOENT) {
        translated = 0;
    }
    int support = integer_property("kern.hv_support", &support_error);
    int hypervisor_guest = integer_property("kern.hv_vmm_present", &guest_error);
    int native_intel = genuine_intel && translated == 0 &&
        (translated_error == 0 || translated_error == ENOENT);
    int attempted = 0, created = 0, destroyed = 0;
    uint32_t create_status = 0, destroy_status = 0;
    int result = 3;
    if (native_intel) {
        attempted = 1;
        create_status = (uint32_t)hv_vm_create(HV_VM_DEFAULT);
        result = 4;
        if (create_status == HV_SUCCESS) {
            created = 1;
            destroy_status = (uint32_t)hv_vm_destroy();
            destroyed = destroy_status == HV_SUCCESS;
            result = destroyed ? 0 : 5;
        }
    }
    char create_text[16] = "null", destroy_text[16] = "null";
    if (attempted) {
        snprintf(create_text, sizeof(create_text), "%u", create_status);
    }
    if (created) {
        snprintf(destroy_text, sizeof(destroy_text), "%u", destroy_status);
    }
    printf("{\"probe_version\":1,\"cpuid_genuine_intel\":%s,\"translated\":%d,"
           "\"translation_query_errno\":%d,\"native_intel_process\":%s,"
           "\"hv_support\":%d,\"hv_support_query_errno\":%d,"
           "\"hypervisor_guest\":%d,\"hypervisor_guest_query_errno\":%d,"
           "\"vm_create_attempted\":%s,\"vm_created\":%s,\"vm_destroyed\":%s,"
           "\"vm_create_status\":%s,\"vm_destroy_status\":%s,"
           "\"guest_execution_performed\":false}\n",
           genuine_intel ? "true" : "false", translated, translated_error,
           native_intel ? "true" : "false", support, support_error,
           hypervisor_guest, guest_error, attempted ? "true" : "false",
           created ? "true" : "false", destroyed ? "true" : "false",
           create_text, destroy_text);
    return result;
}
