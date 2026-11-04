# Native KVM checkpoint component evidence

These are executed component experiments and candidate sources for the complete
KVM checkpoint producer. They are not a production implementation. The current
backend still lacks the required private/shared producer hooks; its
[retained backlog witness](../../../src/backend/kvm/checkpoint_backlog_tests.rs)
remains open. None of these records closes the original four audit findings.

| Component | Verified native evidence | Remaining integration boundary |
|---|---|---|
| [Nested VMX envelope](nested-vmx/README.md) | Header-only 128-byte and active 4224-byte states; source-free VMXON/VMCS continuation and malformed-envelope controls | Complete profile/control admission and CPU/shared transaction composition |
| [Migration MSRs](migration-msrs/README.md) | Fourteen source-free CPU banks; 112 malformed order/membership controls; 28 read-only-value controls | Common clocks, shared aliases, disposable admission and complete transaction |
| [Fixed native banks](fixed-bank-wire/README.md) | Twelve admitted kinds, 142 captured banks and 2272 malformed-packet rejections | Architectural value admission and complete producer composition |
| [SREGS2 record](sregs2-wire/README.md) | Fourteen legacy cache-loss controls, 28 exact source-free restores and 84 malformed-record controls | Full CPU continuation, event/controller association and transaction |
| [Unscaled native clocks](clock-rebase/README.md) | Independent phase-loss controls; 28 serialized phase restores and 228 rejected record/target controls | Actual first-entry gate, other counter/rate profiles and transaction |
| [Combined CPU banks](cpu-banks/README.md) | 28 source-free CPU restores, 84 GPR/XMM/upper-YMM guest outputs, 700 unchanged-destination rejection controls and two combined loaded-VMCS continuations | Production hooks, shared state, clocks, generic I/O settlement and full VM transaction |

The experiments use physical Intel Haswell Linux KVM, the actual installed SDK,
and recorded Rust/C toolchains. The nested VMX and combined CPU witnesses execute
guest code; several other components use stopped native GET/SET interfaces without guest
entry. Their respective receipts distinguish those scopes. They establish no
physical Intel macOS behavior.

SDK 0.14.2 source, manifest, license and verified package provenance are under
[references/sdk-serde-v0.14.2](references/sdk-serde-v0.14.2/). The optional SDK
serialization feature and zerocopy dependency are enabled only by the tiny
companion manifests; the product Cargo.toml/Cargo.lock remain unchanged. The
three wire companions retain their resolved locks. The exact shared production
codec source is archived as [references/rax-codec.rs](references/rax-codec.rs).
The native records contain its SHA-256 identity.

The image formats keep fixed banks separate from dynamic XSAVE, nested state,
SREGS2, controller unions and advancing clocks. Setter success counts are not
treated as value admission or transactional publication. In particular, the
MSR observations retain a real accepted-count/ignored-value counterexample.
CPU source destruction precedes the source-free destination controls.

Each component retains its assumption register and primary sources. The common
evidence boundary is that a successful native component does not prove a
complete checkpoint cut. The production integration still requires:

1. Complete CPU membership, CPUID/capability and memory-layout association.
2. Complete CPU/private, shared controller/timer and native in-flight records.
3. A common native exclusion boundary and a real first-entry clock gate.
4. Multi-exit native I/O settlement and conservation of actual device replies.
5. Full coordinated restoration, rollback and irreversible-failure poisoning.
6. Actual source-free one/two/four-CPU VM-file execution after restoration.

These are high-impact blockers to full checkpoint closure. The component probes
do not replace them. Terminal probe executables have been removed; the one
active native validation cache and immutable source export remain in use.
