# Checkpoint restore admission

Restore admission must validate machine geometry, decompressed reported RAM,
backend state and required device locks before changing live CPU/RAM/device
state. The base checkpoint still represents CPU 0 and four legacy devices; full
SMP/private/platform/PCI closure and VM-wide quiescence remain separate work.

The identical predecessor/current public-API probe covers five nonexact RAM
buffers and eleven VM inputs. The predecessor accepted all five nonexact buffers;
four changed RAM. All eleven malformed VM cases changed CPU/RAM, including four
that returned an error. Cases include corrupt compressed RAM, wrong target
extent/version/architecture/CPU count, reserved MXCSR and RISC-V privilege/vector
geometry, out-of-range x87 TOP and unknown/unsupported active lazy-flag state. This is actual API execution without running a guest CPU or booting.

`GuestMemoryWrapper::try_read_all` provides fallible capture of reported RAM.
`write_all` requires the exact reported length and complete backing coverage;
nonexact or unbacked inputs fail before writing. Existing `read_all` retains its Vec return type and panics if complete capture
is impossible; it cannot return fabricated zero-filled data. Checkpoint capture
uses the fallible operation.

Backend validation is a pure admission operation. x86 uses the existing MXCSR
mask check before register injection. AArch64 uses its existing saved-state and
feature/profile checks. RISC-V validates privilege/vector geometry and acquires
its shared tohost lock before assigning registers, CSRs or vector state. The
default vCPU hook checks the CPU kind. Successful admission does not guarantee a
later native hypervisor ioctl cannot fail; native failure transactions require
separate host/backend proof.

| ID | Assumption / dependency | Stress and falsification probe | Status |
|---|---|---|---|
| A1 | Nonexact restore buffers must not partially overwrite reported RAM. | Lengths 0, 1, n-1, n+1, 2n; exact writes and backing padding sentinels. Any successful mismatch or changed byte fails. | Locally tested; final gates required. |
| A2 | Admission errors must occur before CPU/private/RAM/device mutation. | All eleven actual VM cases and poisoned legacy-device locks; compare complete state and RAM. | Locally tested; final gates required. |
| A3 | Backend preflight preserves existing supported state domains. | Existing direct setter tests, valid x86/AArch64/RISC-V controls and unchanged WARL/vector masking. | Locally tested; final gates required. |
| A4 | Reported RAM is the base format's existing boundary. | Exact capture/restore and unchanged padding; additional writable backing requires an expanded region format. | Explicit existing boundary. |
| A5 | Native setter/host memory failures differ from metadata admission errors. | Actual native backend hosts and complete transactional/private-state proof remain open. | No native transaction claim. |

High impact: full CPU/private/platform state, additional writable backing,
quiescence, per-VM clocks/replay and native setter transactions remain open.
Medium impact: legacy read-all convenience cannot express errors in its Vec
return type; checkpoint callers use the additive fallible API. Low impact:
restoration validation hooks must evolve with backend-private state.

The complete `restore_admission` owner contains 17 tests, including 160 admitted
operation/width/TOP combinations and an unused lazy-flag width that remains a
don't-care. Rejected VM cases compare complete CPU/private/legacy-device payloads
and RAM; the external probe separately retains every RAM byte and CPU markers.
Three library tests cover all four poisoned legacy locks, a poisoned RISC-V
tohost lock, and an unbacked reported-RAM range (including the infallible helper's
explicit panic rather than fabricated output).

The same public-API client reproduces 16 predecessor contract failures: 12 inputs
were accepted and 15 changed state. The current client rejects all 16 with zero
mutations; Python independently checks 65,536 RAM bytes and 176 CPU-marker bytes.
No guest instruction is executed. Inputs, binaries, exact prior library, raw
outputs and source hashes are retained. Native hypervisor setter failures remain
outside this local admission proof.

Reported-RAM capture/restore takes O(n) time for n bytes; fallible capture uses
O(n) additional space. Admission consumes bounded CPU/control work plus O(n)
RAM decompression. Payload decoding and lock acquisition finish before live
assignment. CPU/private validation runs before RAM decoding to preserve early
rejection and the existing x86 error priority.
