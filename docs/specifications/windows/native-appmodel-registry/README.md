# AppModel registry-view acquisition controls

These controls investigate the measured current CMD frontier at
`\Registry\Machine\SOFTWARE\Microsoft\AppModel\Lookaside\machine`.
Qualified runtime 864523b5 observes an ordinary open with access0x80000100,
attributes48bytes/root0/flags0x40 and name Length126/Maximum128bytes. Native
opens return STATUS_OBJECT_NAME_NOT_FOUND; the emulator reports an uncaptured
snapshot. Full process emulation remains the active objective.

This acquisition group changes no guest runtime behavior. Its two existing
Windows 2022/2025 qualification jobs additionally acquire these read-only controls.
Their fresh AMD64 results are pending at this source publication.

## Measured controls

`probe-v1.cpp` and `run-v1.py` are frozen after native execution. The original
verified `capture-v1.zip` retains receipt, compiler logs, raw JSONL and an archive
manifest. Compiler/executable/producer identity, PE machine, optional-header
width and x86 LAA state are recorded. Executables and object/PDB files are
excluded after their identities are retained. `provenance.json` binds the three
immutable files; reference copies have their own URL/date/hash manifest.

Windows 10.0.29695 ARM64 runs four executable views: native ARM64, compatible
x64, x86 and x86-LAA. Each records 64 ordinary/extended opens, plus machine and
completion rows. The 256 calls use fixed AppModel and CurrentVersion paths,
private descriptors/buffers and query-only handles. No key, value, override or
process-wide setting is changed. Handle counts balance in all four runs.

The CurrentVersion control is present in both physical views and supplies
canonical native names through NtQueryKey class3. Each absolute/relative case
crosses flags 0/0x100/0x200/0x300, ordinary NtOpenKey and NtOpenKeyEx option0.
Relative cases use self/Run names and roots opened with three view requests.
The private name-information buffer is 65536 bytes; its length, returned size and
UTF16 byte parity are checked before reading units. User-mode scratch is O(1);
emitted/parsing work is O(U) in the number of recorded name units.

On this ARM64 kernel, direct native64 NtOpenKey does not redirect the logical
CurrentVersion name when view flags are set. The WoW64 thunk redirects absolute
default/0x200 requests to Wow6432Node and 0x100 requests to the 64-bit path;
conflicting 0x300 fails with STATUS_INVALID_PARAMETER. Relative opens retain the
root handle's physical path even when another view is requested. NtOpenKeyEx
option0 agrees with ordinary opens in every paired status/name/tag observation.

Key-body tags depend on the open context. Absolute redirected x86 opens report
0/0x100/0x200 for default/64/32 requests. Relative self/child opens also expose
0x400/0x800 bits in some contexts. The existing shared-snapshot formula cannot
be applied universally. Raw values remain preserved; no meaning for those
additional bits is inferred here. AppModel absence alone proves no present-key
sharing, view-tag or value behavior.

## Reproduce

Retained input verification is portable:

```sh
python3 -B -m unittest discover -s docs/specifications/windows/native-appmodel-registry
```

Fresh physical AMD64 acquisition from an MSVC developer environment:

```powershell
New-Item -ItemType Directory -Force .t | Out-Null
$env:TEMP = Join-Path $PWD '.t'
$env:TMP = $env:TEMP
$env:TMPDIR = $env:TEMP
$env:SystemTemp = $env:TEMP
python -B docs/specifications/windows/native-appmodel-registry/run-v1.py --require-native-machine 0x8664 --output target/native-appmodel-registry-v1
```

Use 0xAA64 for a native ARM64 host. The output path must be new and inside the
source tree. Expected receipt: state finished, exit_code 0, three AMD64-host
views or four ARM64-host views; each producer ends with calls 64 and equal
handles_before/handles_after. Preserve failed records separately from retries.

## Assumption register and scope

| ID | Basis and dependent result | Stress/falsification probe | Status |
|---|---|---|---|
| AM1 | SOFTWARE redirection documentation motivates separate AppModel views | Cross all view flags and ABI personalities; compare canonical native names | Revised: direct native64 NT opens ignore these flags on captured ARM64; WoW64 absolute opens redirect |
| AM2 | A relative open may retain its root handle view | Self/Run under default/32/64 roots, all requests and both APIs; a changed physical prefix falsifies retention | Confirmed within the 64-call captured matrices; independent AMD64 pending |

High: present AppModel data and context-sensitive body tags need corresponding
snapshot behavior; absence is insufficient authority to invent them. This
blocks a complete AppModel adapter, not publication of the acquisition controls.
The current source still stops at the measured CMD frontier. Prior grant/link
metadata boundaries and installed Assist/GUI/real-IDB/package qualification
remain separate open work.

## Primary references

Microsoft's [registry-view table](https://learn.microsoft.com/en-us/windows/win32/winprog64/shared-registry-keys)
classifies SOFTWARE as redirected and describes inheritance by subkeys.
[Alternate-view documentation](https://learn.microsoft.com/en-us/windows/win32/winprog64/accessing-an-alternate-registry-view)
describes Win32 view flags and child-open guidance. The native NT observations
above are distinct from those Win32 rules. Original copies and their provenance
are retained under `references/`.
