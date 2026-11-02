# Fixed MACHINE-root controls

The retained controls observe Windows kernel 10.0.29695 on ARM64. ARM64 code
runs in the native process ABI; x64 and x86 programs run under Windows on ARM.
These results do not establish behavior on an AMD64 kernel or another build.

`probe-v1.c` opens only `\REGISTRY\MACHINE`, queries its grant, tags, header,
canonical name and first value, and closes every successful handle. Its 17
desired masks, four view requests and two open services produce 136 cases per
process ABI. `probe-relative-v1.c` preserves the absolute producer by inclusion,
then opens the empty suffix, fixed NLS CodePage path and fixed AppModel machine
path from three parent views with four child view requests: 36 cases per ABI.
The total is `(136 + 36) × 3 = 516` cases. Both producers compare process handle
counts before and after the campaign. No registry mutation occurs.

`controls-v1.json` retains every original result field, producer SHA-256,
compiler options, executable machine/hash/length, and original report SHA-256.
The producers were formatted before this capture. The controls have a single
`ServiceLastKnownStatus` REG_DWORD value with four bytes `02 00 00 00`, six
children and a canonical name of 17 UTF-16 code units, or 34 bytes. These are
captured data, not defaults for other installations.

The measured ordinary maximum grant is `0x000F003F`. Generic read, write,
execute and all map to `0x00020019`, `0x00020006`, `0x00020039` and
`0x000F003F`, respectively. In particular, generic execute includes
`KEY_CREATE_LINK`. Zero, `SYNCHRONIZE`, `ACCESS_SYSTEM_SECURITY` and the sampled
unknown bit return `STATUS_ACCESS_DENIED` for this token. Selection captures
the actual maximum grant and security-access result; it does not substitute a
read-only grant for `MAXIMUM_ALLOWED`. Other selected keys keep their existing
access profiles.

Native64 view requests have zero tags. WoW64 absolute root tags are 0, `0x100`
and `0x200`; `0x300` is invalid. For relative opens, rows below are parent views
0/64/32 and columns are child view requests 0/64/32:

| Relative target | Parent 0 | Parent 64 | Parent 32 |
|---|---|---|---|
| Empty suffix | 0, 0x100, 0x200 | 0x100, 0x100, 0x200 | 0x200, 0x100, 0x200 |
| NLS CodePage | 0x400, 0x100, 0x600 | 0, 0, 0x600 | 0x600, 0x100, 0x600 |

The fixed AppModel machine leaf is absent in every captured view. Present
AppModel WoW64 body tags remain uncaptured; controlled distinct trees test the
retained view catalog without claiming an independent present-root oracle.
The root routes only to already selected fixed subtrees. A count of six
children does not select arbitrary HKLM descendants. A missing selected tree
and an unselected path remain different outcomes. Canonical NLS names in the
controls use `ControlSet001`; this feature does not add all native key-name
information classes or change the existing selected NLS path spelling.

## Reproduction and gates

From a native Windows checkout with CMake, MSVC, Python and Rust available:

```powershell
python tools/ci/windows_machine_hive.py
```

The runner uses CMake target paths, builds x64 and Win32 producers (also ARM64
when its Python host reports ARM64), checks each PE machine, retains raw JSON
and binary hashes, removes completed native build trees, and supplies the
fresh corpus through `RAX_MACHINE_HIVE_CORPUS`. Guest dispatch replay and the
Windows-only acquisition tests must run with nonzero selection counts and no
ignored tests. Native compile/query failures fail the command. Reports and logs
stay below `target/native-machine-hive-v1`; the existing Windows CI job uploads
that directory. Use a new in-tree `--output` path for another capture so that
prior evidence is preserved.

Portable retained replay and snapshot model checks use:

```sh
cargo test --locked --no-default-features --lib services_tests::registry_tests::machine_hive::
cargo test --locked --no-default-features --lib user::windows::registry::machine_hive::tests::
```

The complete library binary, C API suite, all-target check and native Windows
acquisition remain required qualification beyond these iteration filters.
An installed CMD run and Assist/package validation are separate gates.

## Assumption register and scope

| ID | Assumption and basis | Dependent result | Stress test and falsification probe | Status |
|---|---|---|---|---|
| MH1 | The root is shared across the three process ABIs on 29695; 516 native controls establish grants, metadata and relative tags. | Root selection and dispatcher behavior for this context. | Replay all masks, views and suffixes; compare handle counts and original report hashes. A differing row falsifies the corresponding rule. | Confirmed for the retained context. |
| MH2 | Other supported kernels use the same root-specific mappings and tag transitions. They are not established by Windows-on-ARM x64 execution. | Qualification on AMD64 and other builds. | Run the existing native Windows CI job's fresh producers and replay against the installed snapshot; any differing status, grant or tags falsifies the rule. | Retained pending native evidence. |

The owning no-default-features library binary passed unfiltered on macOS
(8,800 passed, two ignored), Linux (8,790 passed, two ignored), and native
Windows on ARM (8,111 passed, two ignored), with zero failures. The Windows
run also passed all three native acquisition tests, the 191-test C API suite,
the all-target check and ten Windows CLI tests. Its 6,393 normalized source
inputs were unchanged before and after execution.

An actual installed ARM64 CMD `/d /c "echo RAX_MACHINE_HIVE_SNAPSHOT"`
comparison passed the previously unsupported MACHINE-root open and stopped
at the unselected relative `Software\Microsoft\Command Processor` key.
Native CMD exited successfully; guest execution remains incomplete.

High impact, qualification blocker: fresh AMD64 kernel controls are required
before this revision is qualified for that context. Medium impact, existing
boundary: present AppModel WoW64 tags need their own native corpus.
The change does not implement unknown descendants, registry mutation, every
key information class, or complete Windows process startup.
