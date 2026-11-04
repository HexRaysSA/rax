# Explicit KVM SREGS2 wire record

The installed SDK does not give `kvm_sregs2` the checked byte-representation
traits used by the fixed-bank helper. This prototype explicitly retains all
common fields, flags and four cached PAE pointers. It serializes common fields
through a checked legacy-special-register bank with a zero interrupt bitmap;
SREGS2 has no such bitmap. Native event and controller records must retain their
own interrupt state. The decoder admits version 1 and the known
`KVM_SREGS2_FLAGS_PDPTRS_VALID` flag, and rejects unknown JSON fields.

The physical Intel Haswell KVM probe constructed six fresh source graphs:
one, two and four CPUs, each with and without a kernel interrupt controller.
Every CPU had active PAE with cached PDPTR[0] equal to 0x3001 + id * 0x1000,
while the physical table at GPA 0x2000 remained zero. Source CPU/VM owners and
RAM were destroyed before destination construction. All 14 legacy-setter
controls lost the cached pointers. The explicit record made 28 exact native
SET/GET restores: both JSON and the unchanged production RAX codec for each CPU.
All 84 malformed records were rejected without a native state change.

No guest entered. This establishes complete UAPI field transport and native
cached-pointer restoration, not execution after restoration or complete VM
checkpoint replay. [native.json](native.json) retains exact commands, source
hashes and the terminal 776776-byte executable's cleanup. Only the companion
lockfile was resolved; the product Cargo.lock was unchanged. Compiler and
Clippy warnings were confined to unused functions in the copied production codec.

The primary UAPI type, size and field offsets are retained in
[../references/sdk-serde-v0.14.2/src/x86_64/bindings.rs](../references/sdk-serde-v0.14.2/src/x86_64/bindings.rs).
The existing product adapter and cached-PAE counterexample are documented in
[../../kvm-public-state/README.md](../../kvm-public-state/README.md).
The exact executed [record](sregs2.rs), [probe](probe.rs),
[companion manifest](companion-Cargo.toml) and
[assumption register](qualification.json) are retained. The record reuses
[../fixed-bank-wire/bank.rs](../fixed-bank-wire/bank.rs).

| Impact | Remaining boundary | Blocks full checkpoint claim |
|---|---|---|
| High | This component is not integrated into the product | Yes |
| High | CPU/controller/clock/in-flight composition, guest continuation and transaction rollback remain required | Yes |
| Medium | Only the known version-1 UAPI flags are admitted | Future flags require an explicit record revision or admission extension |

Each fixed-size record operation takes O(1) time and space.
