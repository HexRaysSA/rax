# Installed startup terminal diagnostic

CI run 40466793336 passes the installed AMD64 class192 query leaf and then
fails the unchanged original hardware-fault fixture at an unselected
`NtOpenSection` request. Its name and root are unknown from that failure text.

`startup_diagnostics_v1.rs` independently executes the same retained fixture
bytes, configuration and 60 s / 16384-turn / 4096-instruction limits. It requires
exit0 and RTL-owned VEH state. It does not replace, modify or weaken the original
source, binaries, Rust test or assertions. The existing process/SEH CI selection
includes this observer; no job is added.

After terminal failure only, it reads at most eight retained threads. An exact
NtOpenSection failure enables bounded decoding of its arguments, attributes,
root directory and at most 1024 bytes of UTF-16 name data. Raw code units and a
separately rendered string are recorded; truncation and failed reads are
explicit. Checked address additions reject overflow. Windows x64 obtains the
first argument from R10 after SYSCALL; WoW64 retains its transition return slot.
The observer compiles on macOS and Linux, while installed-NTDLL execution runs
on Windows. Output appears under `NATIVE_STARTUP_DIAGNOSTIC_V1` in the test log.

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
| --- | --- | --- | --- | --- | --- | --- |
| SD1 | A terminal service failure retains its thread registers. | `process/services.rs` restores RCX, and `sched.rs` reinserts `Outcome::Fail` threads. | Post-terminal argument decoding. | Native64 and WoW64 argument positions, missing thread or unreadable descriptor. | Compare recorded registers and decoded attributes with the retained service entry and selected namespace. | Retained pending AMD64 capture. |

High impact: the missing section identity and complete AMD64 startup remain
unqualified. The observer changes no shipping behavior, C API, ISA, ABI,
permission, package entry or kernel policy. This diagnostic does not qualify
exception delivery or the full host-library-backed process objective.

The source compiles on macOS and x86-64 Linux under ARM64-hosted Docker;
all eight selected native-entry unit and qualification tests pass on each.
Native ARM64 Windows build29695 passes the independent observer (one test,
ARM64 and x86 both exit0) and all 62 SEH tests, including the unchanged original
fixture. These gates have zero failures and ignored cases. The AMD64 terminal
section identity remains unknown until the existing CI lane executes this
diagnostic. No result here substitutes ARM64 execution for native AMD64 proof.
