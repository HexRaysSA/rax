<!--
{
  "documentType" : "article",
  "framework" : "Hypervisor",
  "identifier" : "/documentation/Hypervisor/extending-vcpu-capabilities-using-model-specific-registers",
  "metadataVersion" : "0.1.0",
  "role" : "article",
  "title" : "Extending vCPU Capabilities Using Model-Specific Registers"
}
-->

# Extending vCPU Capabilities Using Model-Specific Registers

Configure specific client performance monitoring and enable other vCPU capabilities using Model-Specific Registers.

## Discussion

The Hypervisor framework supports managed Model-Specific Registers (MSRs). MSRs covers a wide range of functionality, including enabling guest access to a variety of extended hardware features, such as:

- Enabling `sysenter` and `syscall` instructions for guest OS syscalls.
- Accessing the timestamp counter to measure guest performance or measure time in a guest OS.
- Managing the base address of the FS and GS segment registers.
- Enabling access to extended supervisor state that allows access to certain protected mode register flags.

MSRs are also useful in monitoring guest performance, and using them to customize a vCPU, including:

- Enabling performance counters that make a vCPU to look more like real hardware, allowing guest operating systems to measure app and kernel performance.
- Enabling last branch registers recording in order to gather information useful in debugging crashes in a guest OS or in the apps running in a guest OS.
- Enabling or disabling branch and speculation control in the vCPU to mitigate known security issues for apps running in a guest OS.

To bind and an MSR to the current vCPU, use the [`hv_vcpu_enable_managed_msr(_:_:_:)`](/documentation/Hypervisor/hv_vcpu_enable_managed_msr(_:_:_:)) function. Use the [`hv_vcpu_set_msr_access(_:_:_:)`](/documentation/Hypervisor/hv_vcpu_set_msr_access(_:_:_:)) function to grant or remove the [`HV_MSR_READ`](/documentation/Hypervisor/HV_MSR_READ) or [`HV_MSR_WRITE`](/documentation/Hypervisor/HV_MSR_WRITE) permissions (or both). Unbinding an MSR removes read and write permissions from the guest.

Some MSR facilities require saving and restoring the MSRs in a particular order. The hypervisor framework keeps a list of MSRs that it saves and restores on entry to, and exit from running the guest, along with the rest of the guest state across context switches. In macOS 10 and earlier, the framework appended new MSR requests to the end of the list. When removing an existing request, the framework copied the last entry down to the entry that the framework is deleting. In macOS 11 and later, the framework processes MSRs in the order that they’re added. The MSRs associated with the [`HV_MSR_IA32_PERF_GLOBAL_STATUS`](/documentation/Hypervisor/HV_MSR_IA32_PERF_GLOBAL_STATUS) register have additional requirements, described below, relating to binding of registers to the vCPU.

Because of the variety of possible host hardware, there’s no general formula that’s useful for discovering every MSR supported by the platform. Most approaches to determining specific MSR availability start with executing the `CPUID` instruction to determine the underlying hardware features. Then, using [`hv_vmx_get_msr_info(_:_:)`](/documentation/Hypervisor/hv_vmx_get_msr_info(_:_:)) it’s possible to discover more information about the particular subset of the MSRs that are available.

The example below checks for the availability of one of the speculation control and cache flushing MSRs. Here, a Boolean value, `arch_cap_enabled`, contains the result of a `CPUID` instruction that tests availability of the [`HV_MSR_IA32_ARCH_CAPABILITIES`](/documentation/Hypervisor/HV_MSR_IA32_ARCH_CAPABILITIES) MSR on the Hypervisor host. If successful, the code enables the MSR and grants [`HV_MSR_READ`](/documentation/Hypervisor/HV_MSR_READ) permission to the guest.

```objc
hv_vcpuid_t vcpuid;
if (hv_vcpu_create(&vcpuid, HV_VCPU_DEFAULT) != 0) { // Create a vCPU.
    exit(1, "create_vcpu failed ");
}

bool arch_cap_available = // The result of CPUID invoked with eax=7, ecx=0 returns bit 29 in edx set;
if (arch_cap_available) {
    // The IA32_ARCH_CAPABILITIES MSR is available on this platform.
    ret = hv_vcpu_enable_managed_msr(vcpuid, HV_MSR_IA32_ARCH_CAPABILITIES, true);

    if (ret == HV_SUCCESS) {
       ret = hv_vcpu_set_msr_access(vcpuid, HV_MSR_IA32_ARCH_CAPABILITIES, HV_MSR_READ);
    }

   assert(ret == HV_SUCCESS);

// Arrange to advertise this MSR to the guest via the clients VMX_REASON_CPUID exit handler.

}
```

In the guest OS, test for the availability of [`HV_MSR_IA32_ARCH_CAPABILITIES`](/documentation/Hypervisor/HV_MSR_IA32_ARCH_CAPABILITIES) MSR using the `CPUID` instruction, and then read the register using the following assembly language fragment:

```C
// Check with CPUID to see if this MSR is available.
movl $IA32_ARCH_CAPABILITIES, %ecx
rdmsr
// Returns MSR in <%edx:%eax>
```

> Note:
> The MSRs include several collections of related registers, including ``doc://com.apple.hypervisor/documentation/Hypervisor/HV_MSR_IA32_PMC0``, ``doc://com.apple.hypervisor/documentation/Hypervisor/HV_MSR_IA32_PMC7``, ``doc://com.apple.hypervisor/documentation/Hypervisor/HV_MSR_IA32_PERFEVNTSEL0``, and ``doc://com.apple.hypervisor/documentation/Hypervisor/HV_MSR_IA32_PERFEVNTSEL7``. To avoid repetition, this article refers to these collections as `HV_MSR_IA32_PMCn` and `HV_MSR_IA32_PERFEVTSELn`, respectively when referring to these register sets. A listing of MSR register names is available in the Model-Specific Registers Constants section.

### Analyze Guest Performance

You can use the performance counter MSRs to allow the guest OS to use hardware performance counters to measure aspects of guest performance. These measurements can be in the guest kernel or apps running in the guest OS.

The available performance counters and their capabilities vary greatly across machines and configurations, but include:

- `HV_MSR_IA32_PMCn`
- `HV_MSR_IA32_A_PMCn`
- `HV_MSR_IA32_PERFEVNTSELn`
- `HV_MSR_IA32_FIXED_CTRn`
- `HV_MSR_PERF_METRICS`
- `HV_MSR_IA32_FIXED_CTR_CTRL`
- `HV_MSR_IA32_PERF_GLOBAL_CTRL`
- `HV_MSR_IA32_PERF_GLOBAL_INUSE` (read-only register)
- `HV_MSR_IA32_PERF_GLOBAL_STATUS` (read-only register)
- `HV_MSR_IA32_PERF_GLOBAL_STATUS_RESET` (write-only register)
- `HV_MSR_IA32_PERF_GLOBAL_STATUS_SET` (write-only register)

Because there are complex interactions between the registers, the framework places restrictions on some of these MSRs:

- The framework reserves many of the fields in these registers: setting them to invalid or unsupported values prevents the guest from running. You can determine which bit positions represent available MSRs using the [`hv_vmx_get_msr_info(_:_:)`](/documentation/Hypervisor/hv_vmx_get_msr_info(_:_:)) function.
- The guest can’t set the `HV_MSR_IA32_PERFEVNTSELn` and the [`HV_MSR_IA32_FIXED_CTR_CTRL`](/documentation/Hypervisor/HV_MSR_IA32_FIXED_CTR_CTRL) registers to be directly writable; the client must validate writes to these registers.
- The framework requires enabling the [`VMENTRY_LOAD_IA32_PERF_GLOBAL_CTRL`](/documentation/Hypervisor/VMENTRY_LOAD_IA32_PERF_GLOBAL_CTRL) and [`VMEXIT_LOAD_IA32_PERF_GLOBAL_CTRL`](/documentation/Hypervisor/VMEXIT_LOAD_IA32_PERF_GLOBAL_CTRL) controls. The framework uses these to stop the counters before loading the MSRs.
- The `HV_MSR_IA32_PMCn` and `IA32_FIXED_CTR0n` registers can count more than 32 bits, but the context switches truncate the values to 32 bits (using the MSR write permission) upon restoration of the register state. One way the client can work around this limitation is by enabling the hardware counters without native access, and simulating wider registers through software. The `HV_MSR_IA32_A_PMCn` alias registers can be useful here as they can contain larger values.
- If you bind to the `HV_MSR_IA32_PERFEVNTSELn` event selection registers, then you must bind the corresponding `HV_MSR_IA32_PMCn` registers`,` or its alias registers `HV_MSR_IA32_A_PMCn`. Similarly, if you bind the `HV_MSR_IA32_FIXED_CTR_CTRL` register, you must bind all valid `IA32_FIXED_CTRn` registers.
- The framework doesn’t support native write-access to the `HV_MSR_IA32_PERFEVNTSELn`, [`HV_MSR_IA32_FIXED_CTR_CTRL`](/documentation/Hypervisor/HV_MSR_IA32_FIXED_CTR_CTRL), and [`HV_MSR_IA32_PERF_GLOBAL_CTRL`](/documentation/Hypervisor/HV_MSR_IA32_PERF_GLOBAL_CTRL) registers. The client must intercept and handle writes to these registers to ensure that the guest isn’t given access to unsupported facilities or unbound counters.
- If a full-width alias register — like [`HV_MSR_IA32_A_PMC0`](/documentation/Hypervisor/HV_MSR_IA32_A_PMC0) or [`HV_MSR_IA32_A_PMC7`](/documentation/Hypervisor/HV_MSR_IA32_A_PMC7) — is available in addition to the original [`HV_MSR_IA32_PMC0`](/documentation/Hypervisor/HV_MSR_IA32_PMC0) or [`HV_MSR_IA32_PMC7`](/documentation/Hypervisor/HV_MSR_IA32_PMC7) register, you can only bind one of them to a vCPU at a time. If there’s a binding to either, both MSRs are eligible for guest access.
- You must bind the [`HV_MSR_IA32_PERF_GLOBAL_STATUS`](/documentation/Hypervisor/HV_MSR_IA32_PERF_GLOBAL_STATUS), [`HV_MSR_IA32_PERF_GLOBAL_STATUS_RESET`](/documentation/Hypervisor/HV_MSR_IA32_PERF_GLOBAL_STATUS_RESET), and [`HV_MSR_IA32_PERF_GLOBAL_STATUS_SET`](/documentation/Hypervisor/HV_MSR_IA32_PERF_GLOBAL_STATUS_SET) registers to the vCPU. Use of the latter two registers should be in the order [`HV_MSR_IA32_PERF_GLOBAL_STATUS_RESET`](/documentation/Hypervisor/HV_MSR_IA32_PERF_GLOBAL_STATUS_RESET) followed by [`HV_MSR_IA32_PERF_GLOBAL_STATUS_SET`](/documentation/Hypervisor/HV_MSR_IA32_PERF_GLOBAL_STATUS_SET). The framework ensures the restoration of the status register first, and saves it last when switching contexts. You can grant native access to all three MSRs that map to the underlying status register. The guest global status register [`HV_MSR_IA32_PERF_GLOBAL_STATUS_RESET`](/documentation/Hypervisor/HV_MSR_IA32_PERF_GLOBAL_STATUS_RESET) should be both read and written using [`HV_MSR_IA32_PERF_GLOBAL_STATUS`](/documentation/Hypervisor/HV_MSR_IA32_PERF_GLOBAL_STATUS). Use of the same MSR name is intentional, the framework determines at runtime the right sequence of operations to call). The framework doesn’t support binding this register on processors with architectural performance monitoring version 3 or earlier.
- The `RDPMC` instruction still requires a VM exit to occur. However, if you use the [`HV_VCPU_ACCEL_RDPMC`](/documentation/Hypervisor/HV_VCPU_ACCEL_RDPMC) flag when creating the vCPU, then the kernel automatically handles the `RDPMC` exit, and returns the values of any virtualized PMC register directly to the guest without exiting.

### Record Branch Addresses with Last Branch MSRs

You use Last Branch MSRs when you need to record branching information from guest vCPUs; this can be useful for analyzing and understanding guest crashes.

You can bind Last Branch Register MSRs on more recent processors that support them. However, because of the interdependencies between MSRs, the framework requires that if you bind any of these Last Branch MSRs to a vCPU, you must bind all of them to the vCPU:

- `HV_MSR_LASTBRANCH_n_FROM_IP`
- `HV_MSR_LASTBRANCH_n_TO_IP`
- `HV_MSR_LASTBRANCH_INFO_n`
- `HV_MSR_LBR_SELECT`
- `HV_MSR_LASTBRANCH_TOS`
- `HV_MSR_LASTINT_FROM_IP`
- `HV_MSR_LASTINT_TO_IP`

### Control Security-Related Performance Impacts with Speculation Control MSRs

The framework supports several speculation control MSRs which can impact guest performance, including:

- `HV_MSR_IA32_SPEC_CTRL`
- `HV_MSR_IA32_PRED_CMD`
- `HV_MSR_IA32_FLUSH_CMD`
- `HV_MSR_IA32_ARCH_CAPABILITIES` (read-only register)

For more information about these MSRs, see [CPUID Enumeration and Architectural MSRs](https://software.intel.com/security-software-guidance/insights/deep-dive-cpuid-enumeration-and-architectural-msrs) (Intel Corporation).

The framework’s [`hv_vmx_get_msr_info(_:_:)`](/documentation/Hypervisor/hv_vmx_get_msr_info(_:_:)) function returns the [`HV_MSR_IA32_ARCH_CAPABILITIES`](/documentation/Hypervisor/HV_MSR_IA32_ARCH_CAPABILITIES) MSR value on the platform, and describes the platform-specific capabilities through the [`HV_VMX_INFO_MSR_IA32_ARCH_CAPABILITIES`](/documentation/Hypervisor/HV_VMX_INFO_MSR_IA32_ARCH_CAPABILITIES) value.

---

Copyright &copy; 2026 Apple Inc. All rights reserved. | [Terms of Use](https://www.apple.com/legal/internet-services/terms/site.html) | [Privacy Policy](https://www.apple.com/privacy/privacy-policy)