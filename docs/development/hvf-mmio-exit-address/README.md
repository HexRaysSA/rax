# Intel HVF exit-address authority

A guest CPU can replace a data PDE after a peer's translated EPT exit and before
RAX inspects its page tables. The recorded GPA describes the hardware access;
a new software walk describes later table contents. Treating their disagreement
as an invalid operand permanently fenced the observer before device dispatch.

Exact-source nested Intel run [42169621466](https://github.com/HexRaysSA/rax/actions/runs/42169621466)
at `ce8533a9e43da90f556aa44737ff1221c26864a9` reproduces this: all twelve
sequential controls pass, and all four concurrent guest-writer controls fail.
Their complete CPU tuples retain RIP 0x10028, the second read instruction,
zero reply/continuation markers and the saved mismatch error. The peer's
native guest counter advances in every failing case. Stopping both CPUs and
repairing the PDE does not clear the execution fence.

`baseline-42169621466/` retains all sixteen observation rows, independently
redecoded public projections and all sixteen complete CPU records, totaling
142,872 bytes. `manifest.json` hashes every retained file; `receipt.json` binds
the executable, immutable source inputs and both CI artifact ZIPs. The exact
hardware exit GPA is unknown in failed rows: zero denotes that no request was
exposed by the public CPU API. A containing hypervisor is reported; this is
nested native Intel evidence without a bare-host claim.

The correction uses the qualified GLA/GPA pair for bytes in the first guest
4 KiB page. Every represented scalar load, store, ALU read and RMW shares this
admission boundary. It still validates the decoded effective linear address,
canonicality and supported paging mode, physical width, nonpaged identity,
preserved low twelve address bits and mapped-RAM exclusion. The complete
physical range uses checked addition. The supported physical width remains
32–52 bits. The scalar widths are 1, 2, 4, and 8 bytes. Aligned `CMPXCHG16B`
admits a 16-byte range, which fits entirely in the first 4 KiB page.
[Paired compare-exchange qualification](../hvf-mmio-cmpxchg8b/README.md)

For a decoded linear start L, recorded physical start P and byte offset i:

```text
if page(L + i) == page(L): physical byte = P + i
else:                    physical byte = inspect_current_translation(L + i)
```

Every byte must retain the represented contiguous physical range and target an
MMIO hole. Following pages retain their existing inspection and contiguity
policy. Concurrent changes to those later translations and concurrent code
replacement remain open; this component does not establish general MMIO
coherence. Instruction fetch still uses the nonmutating inspection walker.

Address/mode validation is shared with that walker rather than copied into the
MMIO planner. Data PTE replacement, absence or newly reserved bits cannot
invalidate the first page's already-recorded hardware translation. No CPU,
RAM or device effect occurs while a plan is prepared. Pending input records keep
the original request across a new owner and separately initialized RAM; the SDK
regression checks that observing the held request enters no SDK CPU. Existing
terminal records retain their exact saved failure latch after an upgrade.

The native `combined` profile retains all 952 previous cases and appends the
sixteen coherence controls, expecting 968 ordered records from one signed build:

```sh
python3 tools/hvf/intel_mmio_native_probe.py --profile combined --output <new-directory>
```

The three profile counts 16, 952 and 968 are distinct admission keys. Prepared
artifacts for another profile reject before execution. The standalone
`coherence` profile retains its original sixteen-case ordering.

| ID | Assumption | Basis / dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|
| E1 | Qualified final translated data exits identify the access GPA | SDM086 29.2.1/Table29-7; first-page authority | Changed, absent and reserved current data PTEs | Exit qualifications do not establish a final translated data access | Primary and local gates confirmed; corrected native gate pending |
| E2 | A minimum 4 KiB page preserves its low twelve address bits | Classic x86 page geometry; byte-range arithmetic | All represented widths, offset mismatch and physical-width endpoint | Accepted record changes page offset or exceeds represented physical width | Primary and local gates confirmed; corrected native gate pending |
| E3 | RAM/hole mappings remain stable throughout the public CPU request | VM lifetime read lease excludes mapping publication | Recorded GPA targets RAM while current data tables name a hole | A map writer can publish while the request owns its lease | Source and complete local regressions confirmed |
| E4 | Completing the first MMIO access proves retained stale combined translations | Initial cache-warming interpretation | EPT invalidation rules and sequential controls | EPT violation invalidates the matching combined translation | Falsified as evidence; sequential modes remain controls |
| E5 | Cargo uplifts its library by a hard link | Initial local consumer-builder selection assumption | Compare inode identity and exact SHA-256 | The uplift is a separate copy | Falsified; selecting the hashed library by exact SHA-256 succeeds |
| E6 | The existing 30 s per-program deadline tolerates a concurrent unoptimized library run | Initial root opt-level0 qualification profile | Full run, unchanged executable in isolation, and complete opt-level1 run | A valid closed program exceeds the deadline under the original profile | Falsified for the original run; retained failure, isolated pass, and complete opt-level1 pass are recorded separately |

The primary source permits translation-cache/table disagreement before required
invalidation (Vol.3A 5.10.4.4/5.10.5), but EPT violations invalidate matching
combined translations (Vol.3C 30.4.3.1). No stale cache is inferred from the first
access. The demonstrated failure is the concurrent guest writer changing tables
between exit and software inspection.

For transfer size n, admission is O(n) time and O(1) auxiliary space, with
n in {1, 2, 4, 8, 16} bytes. First-page data admission uses the recorded GPA.

High-impact remaining scope includes following-page and code coherence, other
MMIO/control/interrupt profiles, complete backend/private/in-flight restoration,
VMM startup, clocks and replay. Medium-impact validation scope: CPU tuples permit
PC/failure verification but do not expose the failed hardware exit GPA. No
low-impact adjacent change is required. A32-FP, C-STATE, C-SMP and C-HVF remain
partial.

Primary source: retained Intel SDM086, December 2024,
`docs/specifications/x86_64/325462-sdm-vol-1-2abcd-3abcd-4-1.pdf`, SHA-256
`6f6286056edad4ffdca8716e9039e9598e9e71ab029284facde6a786e1b65f73`.
The address fields and qualifications are Vol.3C 29.2.1/Table29-7, PDF page4139;
combined-mapping creation/invalidation is 30.4.2/30.4.3.1, pages4184–4185.
`exit-address-primary.json` and `primary-verification.json` retain source hashes
and the earlier Vol.3A references.

Complete unfiltered affected binary gates pass: 94 owner tests with debugging, 90 without,
70 MMIO tests and 80 coupled portable tests, 49 Python tests and 16 CI-policy
tests. The full root library reports 12,528 passed, 1 failed and 36 ignored.
All-target build, Clippy and format pass; Clippy reports zero warning lines.
Documentation executes zero examples and ignores five. The signed consumer
compiles with warnings denied; the current read-only decoder correctly reads all
sixteen baseline CPU records. `qualification.json` retains exact commands and
the unrun C/C++ scope. Corrected native execution remains pending.

The initial root library run kept
opt-level0, debug assertions and overflow checks. Non-workspace dependencies
default to task-local opt-level2; existing package-specific overrides, including
sha2 at opt-level3, remain in force. This avoids the previous unoptimized
multi-GiB SHA256 bottleneck. No repository or global profile defaults are changed.

The broad library failure is the closed Darwin runtime test reaching its existing
30 s wall limit for `/usr/bin/true` under concurrent load. After that full run
terminates, the same unchanged Arm64 executable passes the isolated test,
including both system programs. The failing broad result is retained in
`root-library-timeout.txt` and `qualification.json`; it is not relabeled green.
No test deadline, process namespace or production Darwin source was changed.
This is a medium-impact wall-time validation limit, separate from the
modified x86/HVF MMIO execution path.

The [unmodified original audit](../audit-2026-10-source/audit_root_en.md),
sections7.1–7.3, is retained with its source hash. Accepted scheduling and replay
decisions remain in the root remediation ledger; this MMIO component does not
replace the original four-finding acceptance scope.

The second complete concurrent library run, using task-local root opt-level1,
passes all 12,529 nonignored tests with zero failures and 36 ignored. Debug
assertions and overflow checks remain enabled. `qualification.json` records
both full runs and their distinct profiles, without replacing the first failure.

Run42189441259 compiled the exact corrected source, then exceeded the job limit
without an execution artifact. It qualifies zero guest cases. The [command
deadline postmortem](../hvf-command-deadline/README.md) retains build-only
evidence and the separately reproduced supervisor cleanup defect. Corrected
native execution remains pending.

## Native runner disconnect

Run `44346865965` verified the signed consumer and completed the Intel HVF
availability probe. Its last recorded line marks the start of the guest
command. GitHub marked the job failed because the hosted runner lost
communication. The execution artifact is absent and the downloadable job
log returns HTTP 404. The last guest case, the underlying cause, and the
corrected concurrent result are unknown. The signed build qualifies zero
guest cases on its own. [Native job and annotation](https://github.com/HexRaysSA/rax/actions/runs/44346865965/job/134951495358)

The coherence consumer emits case and stage records to stderr before and
after the relevant operations. The records distinguish observer setup,
initial and second MMIO, the peer's first SDK slice, the peer join, private
state capture and teardown. The existing supervisor relays stderr as it
arrives. Guest observation rows and their admission rules remain the source
of pass counts. The diagnostic adds O(1) auxiliary space per case and a
constant number of messages per case, including when the peer loops.

| ID | Assumption and dependent result | Falsification probe | Status |
|---|---|---|---|
| T1 | The existing supervisor preserves early diagnostics in a failed run. | Exercise raw stderr and timeout paths in the complete harness, then look for case stage messages on an Intel rerun. | Local relay tests pass. Remote delivery depends on runner connectivity. |
| T2 | Stage logging remains separate from result admission. | Verify consumer type wiring and run the existing observation admission tests. | Intel x86-64 typecheck and 53 Python harness tests pass. |
| T3 | The runner loss identifies the failure inside the VMM. | Look for a completed execution artifact or a terminal guest error. | Neither is available. The cause below the runner is unknown. |

High-impact remaining work is native verification of the concurrent case.
The first peer log calls can alter host scheduling, which bounds how closely
an instrumented run reproduces timing from the earlier run.
[Runner receipt](native-coherence-runner-loss.json)

## Instrumented native qualification

Run `44361045910` completed all 16 guest cases at
`39a7ed8b465302771875fc48d664c5c026dc3abc`. The signed x86-64 consumer ran
under Hypervisor.framework on a virtualized Intel Core i7-8700B with macOS
15.7.9 and SDK 15.5. All guests reached the post-MMIO marker and produced
terminal CPU records. Verification matched both artifact digests, all 4,767
engine inputs, the executed binary and the 160 logged stages.
[Native job](https://github.com/HexRaysSA/rax/actions/runs/44361045910/job/135002199439)

| Case | Passed | Second exit GPA | Peer iterations observed |
|---|---:|---|---|
| Unchanged mapping | 4 of 4 | `0x40000080` | 0 |
| Replaced mapping | 4 of 4 | `0x40200080` | 0 |
| Replaced mapping with INVLPG | 4 of 4 | `0x40200080` | 0 |
| Concurrent guest page-table writer | 4 of 4 | `0x40200080` | 112,572,256 to 1,698,901,768 |

The concurrent cases confirm successful completion with an active writer.
The run records Intel's EPT GPA and the final page-table entry after the
writer stops. The table value at the moment of each exit is unknown.
Following-page translation, code coherence, and interrupt conservation
require their own native cases.
[Verified receipt](native-coherence-verified.json)
[Guest observations](native-coherence-observations.jsonl)

## Standalone MMIO requalification

Run `44529227554` passed all 952 MMIO, MSR, and existing native VMM controls
at `dacaae9ab251703aedeab104b6a5f3f332ebe770`. Every observation row matched
the prior 952-case record. Verification bound both archive digests, the
executed signed binary, and all 4,825 engine inputs to this result. The
guest consumer used a native Intel process on virtualized macOS 15.7.9
with SDK 15.5. [Native MMIO run](https://github.com/HexRaysSA/rax/actions/runs/44529227554)

During the earlier 968-case combined run at
`89085226695e30d0f6e63887d25075be59d9555a`, GitHub reported loss of runner
communication in the guest step. The signed build artifact verifies against
4,821 engine inputs. The job page retains diagnostic stages through case 966.
Cases 952 through 965 report `complete`. Case 966 records the peer's first
100 ms native slice, the second MMIO observation, the final observer entry,
and `join-peer` at line 173. The peer return is absent from the visible log.
The cause below the logged boundary is unknown. No execution artifact or
downloadable job log is available. The combined attempt provides zero
qualified guest cases. [Combined job transcript](https://github.com/HexRaysSA/rax/actions/runs/44519935525/job/135545645427#step:8:173)

## Guest-controlled peer completion

The concurrent probe's peer polls the observer's reply in guest RAM at
`0xa000`. The observer writes the reply after completing the second device
read. The peer keeps updating the PDE up to that point and then executes
`HLT`, which lets the test join it after a guest-generated exit.

A 64-bit register caps the peer at `2^32` iterations. `HLT` with a zero
counter is a test failure. Success requires a nonzero counter, observed peer
writes, and the exact observer RIP, reply, and continuation marker. The host can
also cancel further peer slices when the observer fails. This bounds guest
work and gives the probe a completion path inside a native slice. The Intel
SDK's host deadline behavior remains a separate requirement.

The 968-case run on `cad6bba69503dcfdfc4ace4f2075caa96ef35e35` also lost
runner communication during the guest step. The signed build artifact matches
4,836 engine inputs and was the only recoverable artifact. The last completed
guest phase is unknown. This run qualifies zero guest cases.
[Combined run](https://github.com/HexRaysSA/rax/actions/runs/44539044643/job/135612177981)
