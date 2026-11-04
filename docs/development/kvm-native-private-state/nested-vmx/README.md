# Native KVM nested VMX checkpoint dependency

These independent kernel and Rust SDK probes establish a required private-state
bank for the complete native checkpoint producer. The proposed `nested.rs` image
helper passes the recorded native experiments. It is not integrated into RAX's
complete producer, and none of the four audit findings is closed by this work.

The native guest executes VMXON, optionally loads a VMCS and writes its
GUEST_RIP field, then exposes an output. A subsequent immediate-exit entry
completes that output before capture. Every source VM, CPU, run mapping and
registered source backing is destroyed before either fresh destination exists.

```text
VMXON -> VMPTRLD -> VMWRITE -> output -> complete output
                                             |
                                  capture and destroy source
                                             |
                           fresh VM + registers/events + RAM
                                             |
                          restore nested record or omit it
                                             |
                             VMREAD -> VMXOFF -> output -> HLT
```

| Native record | Actual bytes | Observed result |
|---|---|---|
| VMXON active, no VMCS loaded | 128 | Private restore permits VMXOFF; public banks and RAM alone lead to shutdown |
| VMCS loaded at GPA 0x9000 | 4224 | Private restore preserves the VMCS pointer and permits continuation |
| Loaded VMCS with GUEST_RIP=0x4142434445464748 | 4224 | VMREAD after source-free restore returns the exact written value |
| Inactive record imported over an active destination | 128 | Active nested state clears; reapplying the saved active record restores continuation |

The host reports a maximum nested-state size of 8320 B. The loaded record here
is a 128 B header plus a 4096 B VMCS12 tail: 128 B + 4096 B = 4224 B.
No active L2 guest or shadow VMCS is exercised by these probes. Setting an L2
guest-RIP field does not mean that an L2 guest was launched.

## Rust SDK return-value boundary

The installed `kvm-ioctls` 0.25.1 `VcpuFd::nested_state()` returns `None` when
the returned size is at most the 128 B header. Its documentation describes this
as absent nested state. The actual kernel observation contradicts using that
value as a complete absence indicator: VMXON is live at GPA 0x8000, is retained
in the header and is required for subsequent VMXOFF.

`sdk-header-only.json` records the actual Rust call returning `None` together
with size=128 and vmxon_pa=0x8000. `header-only-native.json` independently shows
why the record is necessary. The image helper preserves the validated actual
buffer size independently of the optional data-tail length. It also retains
inactive headers so an import can clear stale destination nested state.

The helper checks record bounds, declared length and vendor format before the
native setter. It is an envelope parser, not complete validation of VMCS fields,
CPU-profile compatibility or restore ordering. Six malformed records and an
absent target capacity reject before destination register/private-state
mutation. Actual RAX codec round trips, native recapture equality and continued
guest execution pass for the represented records.

## Evidence and reproduction

`probe.c` is the exact independent direct-UAPI populated-VMCS observer.
`nested-image-v5.c`, `nested-image-v5.rs` and `nested.rs` retain the exact
prototype observation and image implementation. The command receipts preserve
the compiler arguments and dependency identities. `active-vmcs.bin` and
`inactive.bin` retain the actual returned records; their sizes and hashes are
pinned in `provenance.json` and `populated-vmcs-image.json`.

On a Linux x86-64 host with accessible KVM and advertised nested VMX, compile
and execute the independent C observer in an explicitly owned scratch directory:

```sh
cc -std=gnu11 -O2 -Wall -Wextra -Werror probe.c -o /path/to/scratch/probe
/path/to/scratch/probe
```

Its terminal `complete` record reports successful source-free private restore.
Assertions reject unavailable capabilities, unexpected exits and differing
flags/data. Remove the compiled probe after terminal execution. The actual runs
used physical Intel Haswell, Linux 6.8.0-138-generic and GCC 13.3.0. Installed
headers are from Ubuntu 6.8.0-147.147; this version distinction is recorded
explicitly rather than treating header bytes as the running-kernel source.
SDK/header copies and license notices remain unchanged under `references/`.

The first independent probe omitted code/data descriptor S bits and failed VM
entry before VMXON ran. `initial-entry-failure.json` retains that harness error;
it provides no evidence about VMX instruction semantics. Corrected source and
subsequent actual observations are separate receipts.

## Assumptions and remaining requirements

| ID | Assumption and dependent result | Stress test / falsification probe | Status |
|---|---|---|---|
| NEST1 | Public banks and RAM contain the VMX operation state needed for continuation | Destroy the source and resume VMXOFF with versus without nested-state import | Falsified: the public-only target shuts down, and private restore continues |
| NEST2 | SDK `None` means there is no private nested state to retain | Observe the actual header and resume after source-free import | Falsified: a live 128 B VMXON header is required despite `None` |
| NEST3 | The SDK buffer layout can be copied as initialized bytes | Compile-time layout assertions, initialized byte/union storage, actual-size bounds, codec/native recapture and malformed-record controls; a changed SDK layout or differing recapture falsifies this implementation | Confirmed for the pinned SDK and observed 128 B/4224 B records |
| NEST4 | Importing an inactive record clears stale nested state | Active destination, inactive import, native recapture, active reapplication and VMREAD/VMXOFF continuation | Confirmed for the represented root-VMX state on this host |

| Impact | Remaining boundary | Blocks complete native producer |
|---|---|---|
| High | Active L2 execution, shadow VMCS and nested pending events | Yes |
| High | Complete CPU banks, profile admission, shared controllers/timers/clocks, in-flight I/O settling and transactional rollback | Yes |
| High | Integration and actual source-free one/two/four-CPU VM bundles and replay | Yes |
| Medium | Other kernels, CPU vendors and physical Intel HVF | No corresponding validation claim is made |

Envelope processing and storage use O(N) time and space for an N-byte record,
bounded here by the SDK's 8320 B buffer. The complete producer must admit the
entire native profile and field semantics before coordinated publication.
