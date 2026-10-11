# NtQuerySystemInformationEx processor-group semantic group

Baseline: RAX c32061ad587a8d47c6d86e0776676795b85a3e15; Assist
51d248ab4791ff65d0ff67563a022a70d4c85037. Both worktrees were clean.

Acceptance: expose the six-argument operation through the existing admitted
NTDLL service path; implement class 107 / RelationGroup (4) using the guest's
single-processor topology; preserve the measured native-64 and WoW64 lengths,
alignment, fault ordering, guard handling, field conversion, aliases and untouched
suffix. Unsupported relations remain explicit diagnostic stops. Test all guest
ABIs on macOS, Linux and Windows, including selected installed Windows leaf
stubs. Validate owning C API and Assist targets; publish linear commits with
exact staging and red, then update and push the root Gitlink to both remotes.

| ID | Assumption | Basis | Dependent result | Stress test | Falsification probe | Status |
|---|---|---|---|---|---|---|
| A1 | The modeled process has one processor and one processor group. | SystemBasicInformation emits count 1 / mask 1 and process startup writes PEB count 1. | Group maximum/active processor count 1, mask 1. | All three guest ABIs, PEB/query consistency. | A configurable CPU count or affinity consumer disagrees with those existing owners. | retained |
| A2 | Measured native entry and WoW64 conversion behavior applies to the selected 10.0.29683.1000 runtime. | Four independently compiled native probes (ARM64, x64 compatibility, x86, x86 LAA), original hashes retained. | Buffer and fault contract. | Each field boundary, inaccessible extra input/output spans, aliases, guard repeats. | Native oracle differs for any covered case or selected DLL version/hash changes. | retained |
| A3 | RelationGroup is the next request made by this private loader continuation. | Byte-identical owning archive trace stops at svc 0x16E, class 107, four bytes 04 00 00 00. | First supported extended information class/relationship. | Repeat continuation after implementation; inspect exact service arguments. | Repeated owning trace has another class or relationship before this call. | confirmed |

The private continuation restores a previously captured loader context and
clears its modeled heap pointer. It is diagnostic evidence, not an ordinary
process-start success claim. Ordinary native process startup still needs the
separate heap/bootstrap work.

Owned RAX paths: src/user/windows/dll/native.rs;
src/user/windows/dll/native/topology.rs;
src/user/windows/process/sched/tests/services_tests.rs;
src/user/windows/process/sched/tests/services_tests/topology_tests.rs;
src/user/windows/process/sched/tests/services_tests/topology_leaf_tests.rs;
src/user/windows/native-runtime.md;
docs/specifications/windows/native-processor-groups/ (explicit publication list
will be generated before staging). Root owned paths: VENDORED_VERSIONS.md;
src/emulation/native-process-emulation.md; vendor/rax Gitlink.

Change surface: admitted NTDLL service registration and pure guest Windows
system query behavior are affected; loader and scheduler consume the existing
registry without a new service-number table. C API and Assist process targets
compile the changed RAX implementation. Guest instruction execution, SMIR/JIT,
native host kernel forwarding, main-thread/Qt dispatch, UI, agent transport,
permissions, persistence, SDK layout, packages and build defaults are unaffected:
the change adds a pure guest query behind the existing process engine and does
not change their interfaces or configuration. All host platforms compile the
same model and all three guest ABI layouts; only native installed-leaf oracle
tests require a native Windows runtime.

Bounded findings: [high, overall-goal blocker] ordinary native Windows startup
still returns STATUS_ACCESS_VIOLATION; this group does not establish full process
support. [medium, not this group's blocker] the existing full Linux and Windows
suites have explicitly recorded failures outside this query. [medium, not this
group's blocker] the native oracle host has 8 virtual processors / one group;
multi-group and high-mask WoW64 conversion observations remain unknown.
