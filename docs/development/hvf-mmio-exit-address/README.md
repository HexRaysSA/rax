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

Current prepared artifacts bind both the profile name and its case count.
Admission rejects a different profile even when it has the same count. The
standalone `coherence` profile retains its original sixteen-case ordering.

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

Run `45074482995` repeated all 952 cases at
`adf0865cccaf5312451f95655b66188cc5beaac6` with zero failures in 409.09 s.
The observations were byte-for-byte identical to run `44529227554`.
Verification matched both published archive digests, 4,884 engine inputs,
17 consumer inputs, and the executed, signed and entitled binary. The
consumer ran in an untranslated Intel process on virtualized macOS 15.7.9
with SDK 15.5.
[Standalone repeat](https://github.com/HexRaysSA/rax/actions/runs/45074482995/job/137368539126)

- Execution artifact `14774983100`, SHA-256 `90d4e9a3cb3d40df3a5aef18bf3c0c18eb3c40d9459d17ac9ea98552db146d19`
- Observation stream SHA-256 `f316c6b261debf8afb68c175859bfc438d4f71098ee3fae282361d71df7faec1`

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

Standalone run `44550052955` passed all 16 coherence cases at
`d0f38850fa175881dccc6989e82fd05863dbc913`. All four concurrent peers
observed the guest reply and exited through `HLT`, after 76,122 to 262,036
page-table update iterations. Every replacement case reported second-exit
GPA `0x40200080`. The unchanged controls reported `0x40000080`.

Verification matched the signed executable to both artifact archives and
checked all 4,839 engine inputs against the published commit. The guest ran
in a native Intel process on virtualized macOS 15.7.9 with SDK 15.5.
This run covers the standalone coherence profile. Bare-metal Intel execution
and the combined profile remain open.
[Standalone run](https://github.com/HexRaysSA/rax/actions/runs/44550052955/job/135651033256)

A standalone repeat at `073b92a644424b12b593a5cfe9ee62660c689776` retained a
signed build verified against 4,884 engine inputs and 17 consumer inputs.
The executable SHA-256
`3097b3207dd5f0f6a37a6398d0a1100b33ab4bfe36b24519f1c82450a735115c`
matches the executable from combined run `45068548473`.

GitHub reported lost runner communication 2,702 s after the execution step
started. The final visible line records successful capability probing. The
job log has no guest launch marker, and the execution artifact is absent.
Guest entry and the cause of the runner loss are unknown. This repeat
qualifies zero guest cases.
[Standalone repeat and runner annotation](https://github.com/HexRaysSA/rax/actions/runs/45072817649/job/137363381542#step:8:29)

The next standalone repeat at `51cf0733f2e3b0d1fd9d82b036844b77ac6a07d4`
passed all 16 cases in 0.176 s of guest command time. Each of the four
concurrent peers observed the guest reply and exited through HLT after
234,319 to 268,971 page-table update iterations. In those four concurrent
cases, both `0x40000080` and `0x40200080` appeared as the second exit GPA
and each transaction completed at the expected RIP. The page-table entry
at the instant of each exit is unknown.

Verification matched both archive digests, the signed executable, 4,886
engine inputs and 17 consumer inputs. It hashed all 16 CPU records and
confirmed the same 164 case-and-stage pairs as the preceding qualified run.
Some peer stages and observer stages appeared in a different order. The
consumer ran in an untranslated Intel process on virtualized macOS 15.7.9
with SDK 15.5.

- Execution artifact `14779475270`, SHA-256 `36fda11cfccf1807017ad859d820929a78991a425c04b7e03c5cd50fd84cc54a`
- Observation stream SHA-256 `56cb271ec4ea2805ec125fb9f911aa36c549d2c5a1ccd0f0c900c83144f92e63`

[Qualified standalone repeat](https://github.com/HexRaysSA/rax/actions/runs/45084575714/job/137400156874)

## Combined repeat at the packed logical vector revision

Run `45134602279` built and signed the 968-case combined profile at
`a201e8be7d7a03a37df9b4d2d83f8a5169ad596d`. Archive `14800157137`
matched its published SHA-256
`658976008d05e828d253d5e9656c7c43bd57aa379947c105913218e2c3c65475`.
Verification checked 4,901 engine inputs and 19 consumer inputs against Git,
and validated executable
`7e607b8fe99fa5ddea78f5ac2c54a5f3e7d9d2080bc70dc03ab48cb63ddafd1f`
with its signature and Hypervisor entitlement.

GitHub reported lost runner communication 3,019 s after the execution step
started. The run retained only the signed build archive. The job log was
unavailable, so the last guest phase and the cause of the loss are unknown.
This repeat qualifies zero guest cases.
[Combined job](https://github.com/HexRaysSA/rax/actions/runs/45134602279/job/137557764665)
