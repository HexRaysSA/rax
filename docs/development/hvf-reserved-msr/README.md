# Reserved MSR admission control

The baseline Intel HVF handlers returned zero for unknown RDMSR indices and
ignored unknown WRMSR indices while advancing RIP. The independent observations
here establish the required reserved-index fault frontier; they do not yet
qualify a corrected RAX implementation.

Intel SDM revision 086US (December 2024), RDMSR and WRMSR, requires #GP(0) for a
reserved or unimplemented index. The retained [primary manual](../../specifications/x86_64/325462-sdm-vol-1-2abcd-3abcd-4-1.pdf)
contains the rules at PDF pages 1769/1770 and 2777/2778 (printed Vol.2B 4-542/543
and Vol.2D 6-9/10). [Provenance](provenance.json) records the exact PDF hash.

Run on Linux x86-64 with an Intel host and existing access to `/dev/kvm`:

```sh
python3 tools/hvf/intel_reserved_msr_kvm.py --output /tmp/rax-msr-evidence
```

The output directory must be new. Success exits zero and reports 10 cases,
`guest_execution_qualified=true`, and `owned_build_removed=true`. Failure exits
3 and retains command logs and `result.json`. The tool requires the host's
existing KVM `ignore_msrs` setting to be disabled and does not change it.

| Cases | Operation | Required and observed result |
|---|---|---|
| 8 | RDMSR and WRMSR at ffffffff, fffffffe, deadbeef, 20000000 | One #GP with error code 0; saved EIP at the faulting instruction; original EAX/EDX retained |
| 2 | TSC MSR 10 read/write | No #GP; post-instruction marker reached |

The CPL0 32-bit guest installs its own #GP gate, records the frame, skips the
faulting instruction in that handler, and reaches a separate port-output
frontier. That output remains a pending KVM I/O operation: its raw RIP is
recorded without claiming it has completed. Every case creates a fresh VM and
vCPU; normal teardown closes its handles and releases its mappings. An alarm
bounds a defective guest observer and the Python driver removes its own build.

The [ten-case observations](kvm-observations.json) retain host/compiler/source
identity and register/frame values. The [macOS negative control](macos-negative-control.json)
rejects before attempting KVM. The first observer used HLT after creating an
in-kernel irqchip and timed out; that harness failure is retained in provenance.

| Assumption | Stress test or falsification probe | Status |
|---|---|---|
| Reserved-index faults follow the documented Intel contract | Four indices, both directions, actual guest #GP frames, and two valid TSC controls with ignore_msrs=N | Confirmed for this KVM profile |
| Simulated SDK faults can be compared with this architectural frontier | Run pre-fix and corrected Intel SDK-owner regressions for RIP, error code and register preservation | Pending RAX correction |

High impact: KVM implements the virtual MSR policy, so these are independent
native-guest observations rather than direct silicon MSR-policy measurements.
They do not establish Intel macOS HVF execution, complete the TSC-deadline
profile, or close A32-FP, C-STATE, C-SMP, or C-HVF.
