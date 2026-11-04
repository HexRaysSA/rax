# Native KVM fixed-bank wire admission

This prototype serializes 12 sealed, pointer-free SDK structure kinds using
layout-checked zerocopy traits. Each bank carries version 1, a type identifier,
and exactly the native structure size. Deserialization bounds the byte vector
to 4096 bytes; validation rejects another version, kind or length before a
native setter can consume it. Unknown JSON fields are rejected.

The SDK compatibility decoder deliberately pads short images and truncates long
images. The probe observes that behavior for empty and 145-byte register images;
checkpoint admission uses the stricter envelope instead. These are SDK behavior
observations, not claims about a malformed image changing a native CPU.

On physical Intel Haswell Linux with KVM, fresh one-, two- and four-CPU graphs
were captured both with and without an in-kernel interrupt controller. All
142 captured banks round-tripped through JSON and the unchanged production RAX
legacy codec. All 2272 malformed JSON/binary packets were rejected. Each source
VM and all source vCPUs were destroyed before decode. No guest entered, and no
native setter ran during decode. [native.json](native.json) retains commands,
source identities and executable cleanup; [qualification.json](qualification.json)
records the scope and assumptions.

The tiny companion manifest enables the installed SDK's optional serialization
feature and pins zerocopy to the SDK's minimum 0.8.23. Only its own lockfile was
resolved; the product Cargo.lock and source export remained unchanged. Compilation
and Clippy reported unused functions from the exact copied codec module; they
reported no new bank/probe warning. The terminal 1063016-byte probe was removed.

| Native kind | Tag |
|---|---|
| General registers | 1 |
| Legacy special registers | 2 |
| Debug registers | 3 |
| vCPU events | 4 |
| Multiprocessor state | 5 |
| Extended control registers | 6 |
| Local APIC | 7 |
| VM clock | 8 |
| PIT2 | 9 |
| CPUID entry | 10 |
| Segment | 11 |
| Descriptor table | 12 |

Primary SDK serialization and generated layout sources, manifest, license and
package provenance are archived under
[../references/sdk-serde-v0.14.2](../references/sdk-serde-v0.14.2/).
The companion uses the exact source of `src/codec.rs` whose digest is recorded
in the receipts. [bank.rs](bank.rs) and [probe.rs](probe.rs) are the executed
prototype sources. Encoding and decoding consume O(B) time and space for B bank
bytes, bounded above by 4096 bytes.

| Impact | Remaining boundary | Blocks complete checkpoint claim |
|---|---|---|
| High | This component is not integrated into the product | Yes |
| High | Architectural content admission, CPU/shared/in-flight capture, clock restoration, native application and rollback remain separate requirements | Yes |
| High | Dynamic XSAVE, nested state, SREGS2 and IRQchip unions require their dedicated complete records | Yes |
