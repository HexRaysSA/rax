# Native Intel control read shadows on public state import

The public system-register importer wrote guest CR0/CR4 while leaving their
read shadows at constructor defaults (`0x20` and zero). The
[22-case SDK matrix](ram-entry-controls.md) reproduces the native RAX failed-entry
boundary once native MSR bindings are installed. All five variants with full
CR0/CR4 shadows then execute the RAM control to HLT; changing only masks or the
write API does not do so.

The [importer](../../../src/backend/hvf/convert.rs) now writes the supplied
logical CR0 and CR4 to their full SDK read-shadow fields before writing the
guest control-register fields. The existing error path prohibits further CPU
use if any SDK state write fails. This is constant work and storage. No private
record schema changes: the existing VMCS bank already saves both shadow fields,
and raw checkpoint restore continues to restore that bank.

The [public API regression](../../../tests/suites/backend/hvf_intel_owner/native_msr.rs)
imports reset, long-mode, protected-mode and repeated long-mode control values
through the actual backend/owner thread with SDK storage supplied by the test
executable. It requires each shadow to equal the imported value, including
cleared bits after a mode change. It does not execute a guest. The original
converter fails its first CR0 assertion (`0x20` versus `0x60000010`); the corrected
converter passes the focused regression. The complete owner binary passes all
60 tests, with no failures, ignored tests or name filters, including raw bank
restore, rollback and 1/2/4-CPU checkpoint-file transactions. Source inputs stay
unchanged throughout that run. Clippy and the two changed Rust files' formatting
checks also pass. The owned build cache was removed afterward.

The 130-case actual RAX consumer also compiles, links and passes entitlement
signature verification using the corrected library. That local check runs on
Apple Silicon and executes zero native Intel guest cases. Its first direct
link attempt omitted the host dependency search path; adding the same host
and target paths used by the production driver corrected that tooling error.
The temporary consumer compiler directory was removed after verification.

| ID | Assumption | Dependent result | Stress test / falsification probe | Status |
|---|---|---|---|---|
| A1 | The failing RAX RAM control is attributable to stale control read shadows | Native RAX entry correction | Reproduce the failed-entry reason in the SDK matrix; compare full-shadow and mask/API-only variants; rerun the actual RAX consumer | Confirmed through native RAM/MMIO entry in run 41992554080; later private capture fails independently |
| A2 | Updating the two fields preserves raw checkpoint and owner behavior | State-transfer compatibility | Run the complete owner binary, including private bank restoration, rollback, debug/session state and 1/2/4-CPU file transactions | Confirmed within all 60 SDK-model owner tests; actual native continuation remains a separate gate |

High impact: raw SDK CR4/EFER normalization remains visible in the positive
observations, so this correction does not establish every architectural
control-register transition, MSR policy or public-state projection. Medium
impact: the hosted Intel system is a hypervisor guest; bare-metal Intel behavior
is not established. The four full audit findings remain open.

The later actual RAX run passes 118 native cases and then fails its first private
PAT checkpoint because the SDK has changed the producer's control-register
masks. The [mask-policy record](control-mask-policy.md) retains that separate
failure and the constructor correction. It does not qualify a full native run.
