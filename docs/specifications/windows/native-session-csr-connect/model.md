# Current-session native CSR connection model

The model adds `NtConnectPort` with its original eight arguments. The existing
nine-argument secure call keeps its argument positions and measured ARM64
validation. Both use the same bounded input capture, namespace lookup and
process-owned peer/view lifecycle. No guest pointer, name, handle, packet or
request reaches host IPC.

The selected AMD64 startup form is bound to native kernels10.0.20348/26100,
the captured primary session, its selected ApiPort and its independently
captured SharedSection. The section must retain the measured1 MiB extent,
five committed4096-byte pages, statics offset0x750 and matching server pointers.
ARM64 keeps its measured29683/29695/session0 secure form. Other selected-server
forms remain explicit unavailable paths; generic missing-name capture remains
separate from a successful modeled connection.

Native AMD64 acquisition requires native machine0x8664. It reads only this
initialized process's PEB, readonly section prefix and the two NTDLL globals
selected by the verified20-byte PID export. The signed RIP operands and every
code/data span must remain inside the loaded PE image. Unrecognized exports,+kernel/architecture/layout mismatches and unavailable native inputs select no
CSR success profile. The private PID export is never invoked on AMD64.

The AMD64 call ignores the captured QoS Length DWORD, whose native value can
contain stack data. Its remaining measured QoS bytes and request word1 remain
required. The first24 information bytes are outputs; AMD64's other initial
bytes are retained exactly. A successful connection replaces those first24
bytes with server base, statics address and PID, preserves the final24 bytes
and48-byte length, returns maximum952 bytes, and clears the24-byte remote view.
The client view preserves its first32 bytes and receives distinct owned local
and peer addresses for its65536-byte pagefile section.

Output preparation, overlap rejection,136-byte undo storage, rollback,
endpoint duplication and mapped-view generation ownership remain shared with
the existing secure path. At most32 modeled peers each retain their existing
1 MiB frame arena. This is an emulator resource policy, not a native port quota.
Capture costs O(B) time and O(1) transient scratch for B<=1048576 caller bytes;
fixed export decoding, profile checks and output publication cost O(1).

`profiles-v3.json` preserves both raw native reports, encoded stdout, source,
compiler, executable and installed-runtime identities from run40556222401.
Typed projections retain the original bytes and addresses. The decoder test's
minimal enclosing range is a constructed boundary probe; native acquisition
obtains the actual PE image extent. Controlled model tests use owned guest
section handles and VM addresses, compare exact information replies, and
separately prove backing aliasing and lifetime. They do not claim native ASLR
allocation policy. Installed leaves and the immutable full fault fixture
provide separate native-runtime gates.

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
| --- | --- | --- | --- | --- | --- | --- |
| CM1 | The captured primary-session section and initialized client metadata identify one CSR owner. | Independent native replies, PEB/prefix and verified PID globals agree on both AMD64 kernels. | Current-session server selection and reply. | Foreign session, global section, changed pointers, flags and kernel. | Require selected section identity and matching captured fields; native leaf/full fixture. | Native controls confirmed; runtime validation pending. |
| CM2 | The measured AMD64 PID export can be decoded without invoking it. | Both20-byte bodies, bounded operand reads and independent reply-PID agreement. | Readonly host acquisition. | Changed opcode, negative displacement, overflow, out-of-module span, compatibility kernel. | Pure decoder boundary/corpus tests and native acquisition. | Native controls confirmed; runtime validation pending. |

High impact: AMD64 WoW64 startup and further CSR messages still require their
own observed contracts. These remain part of the full Windows objective.
Full Linux/macOS/Windows process emulation, package and installed Assist runtime
qualification remain incomplete. Public C API, ABI, dependencies, defaults and
package layout are unchanged. Original fault source, binaries, Rust test,
assertions and60 s/16384-turn/4096-instruction limits remain unchanged.


Combined-candidate validation passes99 CSR,46 namespace and191 C API tests on
macOS and x86-64 Linux under ARM64-hosted Docker. Native Windows ARM64 passes
101 CSR,48 namespace and191 C API tests. Each selected gate has zero failures
and ignored cases. The unchanged original ARM64/x86 fault fixture also passes.
Native AMD64 adapter compilation, installed leaf and full original fixture
qualification remain pending the existing CI lane. These results do not yet
qualify a clean master source frame, new WoW64/CSR message forms, packages or
an installed Assist runtime.
