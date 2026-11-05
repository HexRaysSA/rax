# SDK DEBUGCTL access and stepping observations

`tools/hvf/intel_debugctl_native.py` observes a fresh Intel Hypervisor.framework
VM for each of sixteen cases. It links no RAX library. The purpose is to determine
whether guest DEBUGCTL access reaches a userspace exit and whether SDK entry
controls load BTF. An absent RAX MSR handler alone cannot answer those questions.

| Case | Guest or host setup | Observation frontier |
|---|---|---|
| read-msr | Guest RDMSR 0x1d9 | Delegated RDMSR, intercepted exception, or HLT |
| write-zero | Guest WRMSR 0x1d9, value 0 | Delegated WRMSR, intercepted exception, or HLT |
| write-btf | Guest WRMSR 0x1d9, value 2 | Same frontier, with DEBUGCTL readback |
| tf | Host DEBUGCTL=0, guest TF=1 | First exception after MOV or later exit |
| btf-default-entry | Host DEBUGCTL=2, guest TF=1 | Compare MOV and taken-JMP frontiers |
| btf-load-entry | Same, with VM-entry load-debug-controls bit 2 requested | SDK rejection or observed entry/exit |

The version 2 probe adds five cases for each of the `native-` and `managed-`
prefixes: `read-msr`, `write-zero`, `write-btf`, `tf`, and `btf`. Native cases
bind DEBUGCTL with `hv_vcpu_enable_native_msr`; managed cases bind it with
`hv_vcpu_enable_managed_msr` and explicitly grant `HV_MSR_READ | HV_MSR_WRITE`.
Both use `hv_vcpu_write_msr` for the host-supplied initial value, while leaving
the initial VMCS DEBUGCTL field zero. This distinguishes an SDK-managed bank
from field-only writes. Version 2 records both VMCS and MSR API readbacks and
the first failed configuration stage. Version 1 records remain readable, and
the retained native six-case report is replayed by the tooling tests.
The [local version 2 qualification](bindings-qualification.json) records all
48 tooling tests and the signed Intel cross-build; it executes zero native cases.

The stepping sequence is `MOV R10, marker; JMP +0; HLT`. CODE is 0x10000;
the MOV ends at CODE+10 bytes and the taken JMP ends at CODE+12 bytes.
The MSR cases prepend RDMSR or WRMSR to `MOV R10, marker; HLT`.
The initial SDK exception bitmap is preserved and #DB/#GP interception is added.
All cases share the previously observed full-shadow RAM setup and constructor
operations. A main-function guard lets both probes compile the same setup.

The report retains raw stdout/stderr, source and executable SHA-256, SDK/OS/compiler
identity, core state, DR6, RDX, DEBUGCTL, pending debug, entry/exit controls,
exit-interruption information and qualification. Optional SDK reads retain their
status and a null value after failure. Configuration rejection is a complete
negative observation with no fabricated entry or exit. Each entry call is bounded
to 0.1 s, at most ten calls; each subprocess also has a 60 s timeout. Setup errors
fail the subprocess; completed observations must report successful resource
release. Temporary executable and signing files are removed by the wrapper.

```sh
python3 -B tools/hvf/intel_debugctl_native.py --output /tmp/hvf-debugctl-observation
python3 -B -m unittest discover -s tools/hvf -p 'test_*.py'
```

On Apple Silicon, use `--compile-only` to compile for Intel, sign and verify
without running a guest. The `native-intel-hvf-availability.yml` workflow executes
all sixteen cases on its Intel runner and uploads them alongside the existing SDK
observations. A successful observation report does not assert ISA conformance,
hardware execution outside a nested host, or RAX guest execution. The separate
RAX native consumer remains the C-HVF execution gate.

| Assumption | Dependent result | Stress test / falsification probe | Status |
|---|---|---|---|
| The shared full-shadow setup can enter this SDK profile | Interpreting an exit as guest behavior | Record entry failure bit, SDK status and core state; compare the existing RAM control on the same runner | Confirmed on the recorded nested host |
| DEBUGCTL access and BTF behavior may be SDK-managed | Whether RAX needs additional MSR dispatch or entry controls | Compare guest access and stepping through field, native and managed banks | Field access delegation confirmed; native/managed execution remains unverified |

## Version 1 native observations

[Run 42108801244](https://github.com/HexRaysSA/rax/actions/runs/42108801244)
completed on source `98f91aee60301069aaf0c25d5af82704d7aae847`.
The [qualification](native-qualification.json) binds all probe inputs to that
Git commit and checks the artifact ZIP SHA-256. Unmodified
[DEBUGCTL output](native-debugctl-42108801244.json),
[availability output](native-availability-42108801244.json), and
[22 RAM controls](native-ram-controls-42108801244.json) retain the raw commands,
observations and cleanup statuses. The process is untranslated Intel i7-8700B,
macOS 15.7.9, SDK 15.5, with `hypervisor_guest=1`.

| Case | First VM exit | RIP | DEBUGCTL before / after |
|---|---|---|---|
| read-msr | 31, RDMSR delegated | 0x10000 | 0 / 0 |
| write-zero | 32, WRMSR delegated | 0x10000 | 0 / 0 |
| write-btf | 32, WRMSR delegated | 0x10000 | 0 / 0 |
| tf | 0, intercepted #DB | 0x1000a | 0 / 0 |
| btf-default-entry | 0, intercepted #DB | 0x1000a | 2 / 2 |
| btf-load-entry | 0, intercepted #DB | 0x1000a | 2 / 2 |

All six cases configured and entered successfully. VM-entry controls were
0x93ff, already including load-debug-controls bit 2. Each stepping exit retained
the MOV marker and reported exit-interruption information 0x80000301 and
qualification 0x4000. Neither BTF case reached the taken JMP frontier at 0x1000c.
The BTF field readback therefore does not establish architectural branch stepping
on this host. Attribution to the SDK or outer hypervisor remains unknown.

The three delegated MSR exits establish that this setup requires a userspace
handler unless native MSR binding changes that behavior. Current RAX dispatch
has no DEBUGCTL case; its default #GP path is a source-derived prediction,
not an executed RAX result from this SDK-only probe. Native MSR enable/read/write
is a separate SDK interface and remains to be compared before choosing the
production execution bank. The existing RAX native consumer run is independent
of these six observations.

## Version 2 native binding comparison

[Run 42110268245](https://github.com/HexRaysSA/rax/actions/runs/42110268245)
completed at `60d0b5e2205f9f07e3fa1f7ac6e8e12884bd0361`.
The [binding receipt](native-bindings-qualification.json) verifies all probe
inputs against that commit and the artifact ZIP checksum. Unmodified
[sixteen-case output](native-debugctl-42110268245.json) and
[host availability](native-availability-42110268245.json) retain the raw evidence.

| Interface | Configuration / entry | MSR instructions | BTF stepping |
|---|---|---|---|
| VMCS fields | Six cases entered | Read and both writes delegated | Both BTF controls trap after MOV |
| Native MSR binding | Five cases entered | Read and both writes still delegated | Traps after MOV; both read APIs retain 2 |
| Managed binding plus READ/WRITE permissions | Binding succeeds; permission setup rejects all five cases with 0xfae94003 (HV_BAD_ARGUMENT) | No guest entry | No guest entry |

There are sixteen complete observations: eleven guest-entry observations and
five configuration rejections. They are not sixteen guest conformance passes.
For every entered stepping case, the #DB interception is at 0x1000a, with the
MOV marker present and the JMP still unexecuted. Native binding does not provide
a working alternate BTF execution bank on this nested host. The SDK and outer
hypervisor contributions remain unknown. These results do not justify adding
a production native binding as a branch-step fix.

High impact, non-blocking for collecting observations: BTF, LBR/BTS and data/I/O
breakpoint profiles still require production-path qualification. This probe
does not close A32-FP, C-STATE, C-SMP or C-HVF.

Architectural provenance: the retained December 2024 Intel SDM
`docs/specifications/x86_64/325462-sdm-vol-1-2abcd-3abcd-4-1.pdf`, SHA-256
`6f6286056edad4ffdca8716e9039e9598e9e71ab029284facde6a786e1b65f73`;
Vol.3B 19.4.1 identifies MSR 0x1d9 and BTF bit 1; 19.4.3 defines branch stepping
and BTF clearing on debug-exception generation; Vol.3C 28.3.2.1 defines loading
DEBUGCTL when the VM-entry load-debug-controls control is set. The observer
records those controls without assuming the SDK exposes the full hardware bank.

The retained Apple article
`docs/specifications/apple/hypervisor-sdk-27.2/native-msr/extending-vcpu-capabilities-using-model-specific-registers.md`
and its adjacent provenance describe managed binding and separate access
permissions. The owning-thread signatures are retained in the parent `hv.h`.
The article explicitly distinguishes discovery of supported MSRs from granting
guest access; neither operation alone establishes correct guest execution.
