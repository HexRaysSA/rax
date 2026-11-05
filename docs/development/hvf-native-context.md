# Intel HVF checkpoint producer

The Intel backend emits producer kind `7` (`HVF_INTEL_CONTEXT`) for CPU and
shared VM records. Current inner tags distinguish `RAXHVI02` and `RAXHVG02`.
The CPU tag versions software-owned architectural PAT state. Explicit
`RAXHVI01` input migrates only when its field schema, disabled link pointer,
valid raw PAT slot, and fixed reset-value architectural PAT are consistent;
ambiguous or malformed records reject before SDK writes.
The shared tag versions the PC RAM geometry: explicit `RAXHVG01` input remains
compatible through 3 GiB; larger legacy flat layouts reject. See
[native PC RAM layout](kvm-native-ram/README.md). The original qualification
record retains the tag used by that earlier run.
Files require both records, the ordered CPU projections, execution/clock state,
and the complete physical backing image. A public register projection alone is
rejected for native restore.

The [qualification record](hvf-native-context-qualification.json) separates
portable admission, SDK-model execution, SDK ABI checks, and physical Intel
execution. The complete audit findings remain open.

## State and admission

Each CPU record retains 25 SDK register values, the admitted guest/control VMCS
schema, six SDK-managed syscall/kernel-GS/TSC-AUX MSRs, and the full host-sized
XSAVE image. It also retains canonical TPR including subclass bits, APIC_BASE,
HLT/shutdown state, a guest TSC time point, deferred input/output continuations,
received input bytes after failed completion, error latches, host step state, and the original running/pending clock binding. Read-only exit information and host-owned VMCS pointers are not writable
restore state. Remaining intercept/exception profiles require separate
qualification.

The public x87 projection retains 80-bit values and reconstructs full tags from
FXSAVE's abridged tags. XSAVE initial components ignore stale register bytes.
Standard MXCSR handling is independent of the SSE in-use bit; compacted images
use their corresponding initialization rule. Public overlays materialize initial
legacy state before marking it in use and preserve opaque host components.
PAT is software-owned architectural state: intercepted RDMSR/WRMSR and public
emulator-state import/export use the same validated value, retained in each
private CPU record. Reserved PAT byte values and unprivileged MSR accesses inject
#GP(0) without retiring the instruction. The SDK-private link-pointer and PAT
VMCS slots are excluded from initialization and checkpoint field banks.
IA32_MISC_ENABLE retains the existing fixed intercepted profile. Architectural
PAT readback does not qualify physical memory-cache-type behavior. The
[native SDK observations](hvf-intel-sdk/README.md) record the constructor failure
and the SDK access restrictions that motivated this change; corrected native
guest qualification remains pending.

The profile identifies guest CPUID configuration, supported host CPUID leaves,
XSAVE component geometry/MXCSR mask, VMX capabilities, admitted VMCS fields,
control policy, and physical TSC frequency when the host supplies it. Host APIC
identity and both current enabled XSAVE-size fields (CPUID leaf `0x0d`,
subleaves 0 and 1, EBX) are normalized. Maximum supported size, component
offsets, and capability bits remain strict compatibility inputs. Destination profile,
CPU identity, complete field banks, public/private projections, topology, and
RAM/MMIO association must agree before publication. No host address is encoded.

CPU payloads are bounded by 1,048,576 bytes of XSAVE state plus 131,072 bytes of
metadata and the 8-byte tag. Shared payloads are bounded by 67,108,864 bytes plus
their tag. Decoders reject unknown versions, truncated/trailing bytes, malformed
field banks, invalid XCR0, and inconsistent pending transactions. These limits
are distinct from the outer checkpoint section limits.

## Publication and rollback

The VM boundary excludes owner requests, IRQ-queue writes, CPU lifetime changes,
and mapping changes. Existing VMM device/RAM guards cover controlled writers;
independent raw aliases still require caller quiescence.

The VMM captures a destination backup before writes. CPU state is programmed
while all owners are stopped, followed by RAM/shared state and derived TPR/TLB
publication. A partial SDK failure fences ordinary entry. Rollback restores
CPU/private state, RAM, and shared state, including the original host-clock
binding and VM epoch; failed rollback poisons the VM so peers
cannot enter or capture a partially restored machine.

Forward VM restore retains the current debugger's MTF and #DB/#BP controls and
clears stale completion notifications. Rollback uses the original destination
notification state. Raw CPU-context import uses the captured debugger payload;
it is a CPU operation and requires independent device consistency from its
caller. A raw import containing host debug controls requires the `debug` feature.
Guest RFLAGS.TF remains independent of that host capability.

All scoped CPU captures use one `hv_tsc_clock` anchor. After restore, owners
rebase their captured guest time points against one shared resume epoch on their
next attempted SDK entry. Rollback restores the original running or pending clock domain, so time spent in
a failed restore is retained in an already running host-clock relation. Offset
arithmetic is modulo 2^64. This preserves the
supported host-clock relation; it does not provide an exact retirement counter,
a deterministic replay clock, or native SMP scheduling. The relative-clock APIs
are resolved at runtime and require their macOS 11-or-later SDK availability;
missing APIs cause explicit admission failure.

## Evidence boundary

`hvf_intel_owner` executes the production Intel backend and VMM through Rosetta
with SDK functions supplied by the test executable. It covers real `.rxc` file
round trips, pending I/O, debugger publication/rollback, clock rebasing, and
injected partial SDK failures. It creates no physical Hypervisor VM and executes
no native guest instruction. Portable library tests cover XSAVE projection and
record admission without the native SDK.

Physical Intel guest execution, remaining native intercept/MSR and MMIO profiles,
IRQ/device coherence, bounded native scheduling, and replay remain separate
open gates. See the [audit ledger](audit-remediation-2026-10.json).
