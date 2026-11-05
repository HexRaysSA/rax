# SDK-only RAM-entry control matrix

The [native RAX diagnostic](native-entry-failure-41983036300.txt) now identifies
failed entry `0x80000021`, with unchanged initial RIP and R10. The cause remains
unknown. The [write-only SDK observer](sdk-control-writes.md) establishes
pre-entry readbacks, which do not determine entry-time behavior.

The [C observer](../../../tools/hvf/intel_ram_entry_native.c) links only Apple's
Hypervisor framework. It recreates the initial Rust consumer's 2097152-byte
RAM image, identity page tables, descriptors and `MOV R10, imm64; HLT` control.
Each variant runs in its own process with a fresh VM and vCPU. The guest bytes
and initial architectural state remain fixed; the following transfer settings
vary. The original observer omitted RAX's FP-image installation, native-MSR
bindings and relative-TSC initialization; those omissions are now independent
constructor controls.

| Variant | Full CR0/CR4 read shadows | SDK-required masks | SDK-required guest CR0/CR4 bits | CR0/CR4 write API | Add VMXE to CR4 and its mask |
|---|---|---|---|---|---|
| baseline | No | No | No | VMCS | No |
| full-shadows | Yes | No | No | VMCS | No |
| required-masks | No | Yes | No | VMCS | No |
| required-masks-and-shadows | Yes | Yes | No | VMCS | No |
| register-controls | No | No | No | Register | No |
| register-controls-and-shadows | Yes | No | No | Register | No |
| required-state-and-shadows | Yes | Yes | Yes | VMCS | No |
| vmx-masks-and-shadows | Yes | Yes | Yes | VMCS | Yes |

With `--constructor-matrix`, the driver runs 22 observations: these eight
variants with constructor flags zero, the baseline with flags 1 through 7,
and the other seven transfer variants with flags 7. Flags compose as follows.

| Bit value | Constructor operation before public-state import |
|---|---|
| 1 | Enable and zero the six native syscall/SWAPGS/RDTSCP MSRs |
| 2 | Call `hv_vcpu_set_tsc_relative(cpu, 0)` |
| 4 | Read and reset the host-sized XSAVE image with XCR0 set to 1 |

Every record identifies its exact constructor flags and schema version 2.
All operations use the current SDK on the process's owning thread. This
reproduces those constructor operations; it does not establish equivalence to
every RAX owner/resource setup path.

The baseline uses CR0 mask/shadow `0x20` and CR4 mask/shadow zero, matching the
current RAX initializer. Full shadows contain logical CR0 `0x80010033` and CR4
`0x220`. Required bits are queried from the current SDK with
`hv_vmx_vcpu_get_cap_write_vmcs`; its
[primary header](../../specifications/apple/hypervisor-sdk-27.2/hv_vmx.h)
defines the two returned masks. These variants are observations, not proposed
production policies or a proof that all required bits should be exposed to a
guest.

Before and after entry, every record retains CR0/CR3/CR4, EFER, CR0/CR4 masks
and shadows, pin/primary/secondary/entry controls, CS access rights, activity, interruptibility, RIP,
R10, RAX, RDI and RFLAGS. Entry uses `hv_vcpu_run_until`, whose
[SDK contract](../../specifications/apple/hypervisor-sdk-27.2/hv.h) specifies a
Mach absolute-time deadline. Each call allows 100 ms; at most ten calls continue
through deadline exit 52 or host interrupt exit 1. No failed entry is retried. The wrapper also bounds
each owned process to 60 s. Its temporary compiler/signature directory is
removed on success and failure.

A positive SDK variant requires exit reason 12 (HLT), RIP `0x1000a` at the HLT
instruction, R10 `0xa1b2c3d4e5f60718`, unchanged RAX/RDI, and RFLAGS 2. RAX's
public HLT exit advances RIP to `0x1000b`; this observer reads the raw SDK state.
API failures retain a null exit reason. The observer also attempts
`hv_vcpu_vmx_status` and reads VM-instruction error field `0x4400`, retaining
each actual read status and a null value after a failed read. The
[SDK header](../../specifications/apple/hypervisor-sdk-27.2/hv.h) specifies that
the VMX flags refer to the last unsuccessful run attempt; an instruction-error
read alone does not establish a valid current VMX failure diagnosis.
A complete matrix may contain only failed attempts:
failed entries: the wrapper's success flag means complete observation, and
`rax_guest_execution_qualified` always remains false. Positive SDK variants
are reported separately.

```sh
python3 -B tools/hvf/intel_ram_entry_native.py --constructor-matrix \
  --output /tmp/rax-entry-observation
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s tools/hvf -p 'test_intel_ram_entry_native.py' -v
```

The output directory must be new. On an Apple Silicon host, `--compile-only`
checks x86-64 compilation, linking and ad-hoc entitlement signing. Normal
execution refuses a translated process before VM creation. The manual
`native-intel-hvf-availability.yml` workflow runs the matrix on Intel macOS and
retains its result even when another step fails. The initial local validation
and native RAX failure are recorded in [qualification](ram-entry-qualification.json).
The initial eight-case matrix in
[run 41988534104](https://github.com/HexRaysSA/rax/actions/runs/41988534104)
completed all observations, but all eight returned SDK `HV_ERROR`
(`0xfae94001`) with no exit reason and unchanged state. Its
[raw result](sdk-ram-observation-41988534104.json) is retained unchanged.
This differs from RAX's successful SDK call followed by failed-entry reason 33;
it cannot distinguish the original transfer hypotheses. The expanded
constructor matrix has not yet run on native Intel at this publication.

| ID | Assumption | Dependent result | Stress test / falsification probe | Status |
|---|---|---|---|---|
| A1 | The original SDK-only baseline reproduces RAX's failed-entry boundary | Interpretation of the matrix | Compare SDK run status and exit/state with the native RAX failure | Falsified: the original observer returns API error without a VM exit; constructor matrix pending |
| A2 | Pre-entry equality proves equivalent entry behavior for the two write APIs | Choosing a production transfer implementation | Compare VMCS and register variants through actual guest entry | Unproven; no production API change made |

High impact: native RAX entry remains unqualified; a positive SDK variant alone
does not close C-HVF. Medium impact: the hosted Intel machine reports itself as
a hypervisor guest, so its result does not establish bare-metal Intel behavior.
The fixed variant inventory and bounded guest entries use constant time and space
with respect to guest inputs. No other audit finding is marked complete here.
