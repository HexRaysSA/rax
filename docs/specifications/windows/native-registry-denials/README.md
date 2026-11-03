# Inaccessible installed IFEO descendants

Installed Windows registry selection retains an enumerated IFEO child whose
body denies access, rather than aborting acquisition of every selected root.
The fixed IFEO parent supplies ordered child names, last-write timestamps and
subkey counts. Accessible bodies retain their captured raw values. A denied
body supplies no invented values, native handle or retained host callback.

The capture adapter accepts this representation only after query/enumerate
access fails with Win32 error 5 and independent native opens for
`MAXIMUM_ALLOWED`, `ACCESS_SYSTEM_SECURITY`, then `MAXIMUM_ALLOWED` all return
`STATUS_ACCESS_DENIED` (`0xC0000022`). Partial grants, distinct privilege failures
and inconsistent observations remain explicit acquisition errors. Root errors
retain their previous meaning. Guest-provided paths, access masks and handles
are never forwarded to these selection-time operations.

A final ordinary open of the retained denied node returns its captured denial.
Lookup resolves the whole name first: zero observed subkeys proves a missing
descendant, while a positive count leaves unknown descendants explicitly
uncaptured. Backup/restore with enabled privileges also remains explicitly
uncaptured because no body was acquired for that token policy.

## Native controls

The two C++ producers perform read-only opens of fixed subjects and enumerate
the IFEO parent. The ordinary-user receipts record the same SID and NTDLL hash;
they do not independently identify the kernel build or establish other Windows
versions, token subjects or architectures.

| Control | Open cases | Enumeration cases | Opened/closed handles |
| --- | ---: | ---: | ---: |
| Ordinary masks | 84 plus parent | 66 | 1/1 |
| Security and generic masks | 156 plus parent | 66 | 1/1 |

Both absolute and retained-parent routes deny the protected child, including
case folding and a trailing separator. Missing children, including a missing
descendant beneath that protected child, return `STATUS_OBJECT_NAME_NOT_FOUND`
(`0xC0000034`). A blanket denial for every path sharing the child's prefix
would contradict these observations.

Parent enumeration still exposes `DefenderAgentScan.exe`, its timestamp and
its zero subkey count. Basic, Node and Full information require 58, 66 and
44 bytes respectively in this sample. The Full header reports one value;
the producer does not read that value. `verify-evidence.py` checks all open
results, the complete boundary/poison grid, every returned byte, source and
stdout hashes, and balanced handles.

The native Rust receipt records nine passing tests from the actual RAX test
executable: four read-only capture-adapter cases, three portable snapshot
cases and two entered-service cases across every `WinArch`. Its source
manifest joins the owned production/test bytes and executable hash to the
host build; it does not assert a native rebuild. Portable macOS tests and
strict root-library Clippy also pass. The first broad portable run passed
244 cases and exposed one incorrect WoW64 test expectation; correcting that
expectation left shared production bytes unchanged, and all five new portable
cases then passed. WoW64 preserves its existing denial-before-null-output
ordering; native64 retains its earlier output probe.

Microsoft documents parent enumeration access, unstable enumeration indices
and the user-mode `NtEnumerateKey` name in
[ZwEnumerateKey](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwenumeratekey).
The [KEY_FULL_INFORMATION layout](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_key_full_information)
defines `SubKeys` and FILETIME units. The adapter uses its fixed 44-byte header,
with `SubKeys` at byte offset 20; it compares two poison-initialized samples and
the independently enumerated timestamp before retaining that count.

```sh
python3 -B docs/specifications/windows/native-registry-denials/verify-evidence.py
cargo +1.95.0 test --locked --offline --no-default-features --lib registry::captured_tree::tests
cargo +1.95.0 test --locked --offline --no-default-features --lib registry_tests::denials
# On Windows, exercise the actual read-only capture adapter:
cargo +1.95.0 test --locked --offline --no-default-features --lib registry::installed::ifeo::tests
```

Capture visits each selected key once, with a bounded number of stability
samples and balanced native handles. For K keys, E enumerated name units and
V value bytes, tree construction costs O((K + E) log(K + 1) + V) time and
O(K + E + V) retained space, subject to existing snapshot limits. Metadata
attachment uses ordered-map lookup per key. Runtime open semantics use the
same immutable snapshot on Windows, macOS and Linux; native acquisition is
compiled only on Windows. This change does not establish complete installed
Windows process startup. The next ordinary-user CMD construction attempt
passes registry acquisition and fails later with
`NtQueryDirectoryObject selected namespace: 0xc0000022`, before guest execution.
That object-directory acquisition failure is a separate remaining blocker.
