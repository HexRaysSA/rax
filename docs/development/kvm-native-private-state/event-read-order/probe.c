#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/kvm.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

static void require(int status, const char *operation) {
    if (status < 0) {
        fprintf(stderr, "%s: %s\n", operation, strerror(errno));
        exit(2);
    }
}

int main(void) {
    int kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    require(kvm, "open KVM");
    if (ioctl(kvm, KVM_CHECK_EXTENSION, KVM_CAP_EXCEPTION_PAYLOAD) <= 0) {
        fputs("exception payload unavailable\n", stderr);
        return 3;
    }
    for (int payload_enabled = 0; payload_enabled < 2; ++payload_enabled) {
        for (int vector_index = 0; vector_index < 2; ++vector_index) {
            int vector = vector_index ? 14 : 1;
            int vm = ioctl(kvm, KVM_CREATE_VM, 0);
            require(vm, "create VM");
            struct kvm_enable_cap cap = { .cap = KVM_CAP_EXCEPTION_PAYLOAD,
                                         .args = { 1 } };
            require(ioctl(vm, KVM_ENABLE_CAP, &cap), "enable payload for setup");
            int cpu = ioctl(vm, KVM_CREATE_VCPU, 0);
            require(cpu, "create CPU");
            struct kvm_sregs special = {0};
            struct kvm_debugregs debug = {0};
            require(ioctl(cpu, KVM_GET_SREGS, &special), "get initial SREGS");
            special.cr2 = 0x1111222233334444ull;
            require(ioctl(cpu, KVM_SET_SREGS, &special), "set initial SREGS");
            require(ioctl(cpu, KVM_GET_DEBUGREGS, &debug), "get initial debug");
            debug.dr6 = 0xffff0ff0ull;
            require(ioctl(cpu, KVM_SET_DEBUGREGS, &debug), "set initial debug");
            struct kvm_vcpu_events events = {0};
            events.flags = KVM_VCPUEVENT_VALID_PAYLOAD;
            events.exception.pending = 1;
            events.exception.nr = vector;
            events.exception.has_error_code = vector == 14;
            events.exception.error_code = vector == 14 ? 5 : 0;
            events.exception_has_payload = 1;
            events.exception_payload = vector == 14 ? 0xfeed123456789abcull : (1ull << 14) | 2;
            require(ioctl(cpu, KVM_SET_VCPU_EVENTS, &events), "queue payload");
            cap.args[0] = payload_enabled;
            require(ioctl(vm, KVM_ENABLE_CAP, &cap), "select capture payload profile");

            struct kvm_mp_state mp = {0};
            struct kvm_sregs before_special = {0}, after_special = {0};
            struct kvm_debugregs before_debug = {0}, after_debug = {0};
            require(ioctl(cpu, KVM_GET_MP_STATE, &mp), "get MP state");
            require(ioctl(cpu, KVM_GET_SREGS, &before_special), "get SREGS before events");
            require(ioctl(cpu, KVM_GET_DEBUGREGS, &before_debug), "get debug before events");
            require(ioctl(cpu, KVM_GET_VCPU_EVENTS, &events), "get events");
            require(ioctl(cpu, KVM_GET_SREGS, &after_special), "get SREGS after events");
            require(ioctl(cpu, KVM_GET_DEBUGREGS, &after_debug), "get debug after events");
            printf("{\"payload_enabled\":%d,\"vector\":%d,\"cr2_before\":\"%016" PRIx64 "\","
                   "\"cr2_after\":\"%016" PRIx64 "\",\"dr6_before\":\"%016" PRIx64 "\","
                   "\"dr6_after\":\"%016" PRIx64 "\",\"pending\":%u,\"injected\":%u,"
                   "\"payload_retained\":%u,\"event_flags\":%u}\n",
                   payload_enabled, vector,
                   (uint64_t)before_special.cr2, (uint64_t)after_special.cr2,
                   (uint64_t)before_debug.dr6, (uint64_t)after_debug.dr6,
                   events.exception.pending, events.exception.injected,
                   events.exception_has_payload, events.flags);
            close(cpu);
            close(vm);
        }
    }
    close(kvm);
    return 0;
}
