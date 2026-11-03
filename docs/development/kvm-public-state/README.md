# Native KVM public register state

The KVM adapter reads and overlays its kernel-representable public x86 register banks:
GPRs, segments and control registers, debug registers, the seven represented
SYSCALL/SYSENTER MSRs, MMX aliases, XMM/YMM, and the host-admitted ZMM/opmask banks.
This is a public-register prerequisite for the complete native checkpoint
producer. It does not supply that producer.

| State | Public overlay behavior |
|---|---|
| Public GPR, vector, debug and syscall banks | Read native values and publish requested values |
| APIC_BASE and pending interrupt bitmap | Retain native fields omitted from SystemRegisters |
| Unrelated special-register changes | Use SREGS2 and retain cached PAE PDPTRs |
| Changed PAE CR3 | Load the requested new page-directory-pointer table |
| Pending NMI/interrupt and shadow fields | Retain the native event record |
| Active x87 controls, exact 80-bit upper words, MXCSR and other XSAVE components | Retain unprojected architectural state |
| Unexposed APX register values | Reject before native writes |
| Input awaiting caller completion | Reject the public overlay before mutation |
| Failed setter | Restore the native backup; prohibit that CPU's entry if rollback fails |

The kernel's complete XSAVE allocation size comes from the VM's
KVM_CAP_XSAVE2 query. Allocation additionally covers the host CPUID.0DH user
component image, with a 1 MiB limit. A negative capability-query result is an
error; only zero selects the legacy ABI. The host architectural FXSAVE
MXCSR_MASK supplies the supported bits, including DAZ when available. An
unchanged public vector bank retains the original initialization/component bits.
The existing native x86 XSAVE projection and overlay utility is shared with HVF.
No ISA interpreter, lifter, C ABI layout or snapshot wire format changes here.

A native counterexample showed that skipping only identical SREGS images was
insufficient: a CR8-only edit reloaded cached PAE pointers from changed RAM.
SREGS2 now carries the actual cached pointers through unrelated special-register
edits and rollback, while a changed CR3 requests a new table. Older kernels
without SREGS2 reject changes to an already-active PAE special-register bank
before publication, since they cannot preserve or roll back that hidden cache.

A public overlay prepares its buffers before native writes. A rejected kernel
control-register write exercises rollback of earlier vector, MSR and debug
writes. This per-CPU operation does not provide a complete VM transaction.
Register-image preparation takes O(B + C^2) time and O(B + C) storage for B
image bytes and C extended-component descriptors. Pairwise layout validation
accounts for C^2; the architectural component mask bounds C to at most 61.

Managed CPUs retain the native VM and its registered backing after the caller
drops the VM/RAM handles. Registration retains submitted backing before the
first slot ioctl, including a partially failed registration. Old registration
backing is conservatively retained until the native owner is destroyed.

## Native evidence and initialization

The native witnesses use the existing abyss Linux x86-64 test host with writable
/dev/kvm. They execute the actual RAX KVM adapter, including guest MMX/XMM stores,
input completion, and RAM access after dropping caller-owned handles. Native
cases are explicitly ignored in ordinary portable test runs; the KVM CI job
executes the complete public-state module with --include-ignored.

The independent original-module probe executes a guest MOVDQU load before
calling the unchanged original KVM getter. Its nonzero hardware XMM value is
projected to zero by the original backend. The surrounding standalone harness
uses public-register type excerpts and minimal traits, so this is an isolated
original-module baseline, distinct from execution of the complete RAX crate.

The first floating-point fixture incorrectly assumed that KVM_SET_FPU activated
operative XSAVE state. On the observed kernel it leaves the component bits
inactive: GET_FPU reports the dirty legacy buffer while GET_XSAVE2 and actual
guest instructions observe architectural initialization. A separate C guest
retains this counterexample. Corrected fixtures seed the standard legacy fields
and x87/SSE active bits through KVM_SET_XSAVE. They preserve the original expected
register values and also check the inactive-state case. Kernel legacy GET_FPU
also does not provide MXCSR; its preservation is checked in the XSAVE image.

The retained primary API reference is Linux v6.8 api.rst, particularly the
GET/SET_FPU, GET/SET_XSAVE, GET_XSAVE2, GET/SET_VCPU_EVENTS and SREGS2 interfaces.
Its section 5 requires completion of pending I/O before migration. The retained
x86.c and FPU sources explain the legacy buffer and XSAVE normalization behavior.
Intel SDM Volume 1 Chapter 13 and the FXSAVE/XSAVE instruction descriptions define
the architectural component table and initialization rules. Exact source URLs
and hashes are in references/provenance.json.

## Required remaining work

All four original findings remain open. Complete KVM private/shared/in-flight
producer records, coordinated VM restoration and source-free checkpoint files
are still required. A separate ignored native witness retains the missing
private-producer requirement. Native host deadlines and actual VMM AP startup
remain required for C-SMP. Raw FD escape lifetime remains a separate open issue;
the managed-owner fix does not close it. Native Intel macOS HVF execution and the
remaining A32/HVF requirements are not qualified by Linux KVM execution.

Native followup probes retain two additional requirements. The current RAX
registration path turns a RAM read at physical 0x100000000 into an MMIO exit.
Adding only the independently installed, aligned high-RAM slot lets the same
guest read backing byte 0xa5 and halt. Correcting the full RAM/device layout and
PC boot memory map remains required; this group does not supply that correction.

An external deadline prototype also enters the actual RAX adapter for 40 finite
turns and preserves an IN/OUT/HLT sequence across worker returns, together with
the caller's signal mask and existing handler. It does not implement production
`run_host_slice`. The observed 2 ms requested interval took approximately
3.06--20.1 ms including worker scheduling on this host; this is not a hard
real-time bound. Exact receipts and the earlier short-interval high-RAM probe's
unresolved entry-limit failure remain in qualification.json.

See qualification.json for current verification status and observed limitations.

## Final verification scope

test result: FAILED. 13122 passed; 4 failed; 20 ignored; 0 measured; 0 filtered out; finished in 5768.24s

The full owning library run completed on the061f6 upstream base, with four
unrelated socket/netlink harness failures retained in qualification.json. Native
public-state regressions pass14/14 in debug and default profiles. The later
Windows registry and Unix socket-test changes were fast-forwarded without a
merge and verified separately on the b80e2954 integration base, together with the
workspace build, Clippy and formatting gates. No physical Intel macOS execution
is established by these Linux KVM checks.

Imported Linux references and frozen counterexamples retain their original bytes.
The per-path attributes preserve line endings and retain four upstream
space-before-tab indentation patterns in two primary files; other whitespace
checks remain enabled.

A later Windows session-namespace change was fast-forwarded at d548e62f. Its
files are outside this group and were not retested by these earlier gates. All
KVM inputs and Cargo manifests remained unchanged; staged and next-group file
hashes were verified before and after the fast-forward.
