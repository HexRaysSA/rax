# Directory cursor fixtures independent of host order

Three Windows-personality tests assumed that a directory query returns `"."`
first. All three failed on the recorded Linux filesystem, where the observed
first entry was `"subdir"`. The original complete five-test namespace reported
two passes and three failures. This is a fixture-order counterexample, without
a production directory-enumeration change.

| Contract | Fixture correction |
|---|---|
| Duplicated handles share a cursor; independent opens have their own cursor | Use the unique `alpha.txt` expression: first handle succeeds, duplicate reaches EOF, independent open succeeds |
| A no-update query leaves the normal cursor untouched | Compare the next normal query with the first entry from an independent unmodified open on the same fixture |
| Access denial and failed guest-output capture do not consume an entry | Retain both failure checks, then require the unique `alpha.txt` result |

Restart/filter replacement, record layouts, guest publication and status checks
remain in place. The existing test loops retain all three guest ABIs and both
directory service families where previously exercised. The
[Microsoft primary source](../../specifications/windows/native-directory-enumeration/primary/microsoft-nf-ntifs-ntquerydirectoryfile.md)
documents expression capture and scan continuation; the
[native directory profile](../../specifications/windows/native-directory-enumeration/README.md)
retains the separately measured Windows behavior. These fixture changes add no
new Windows runtime claim.

[Qualification](directory-qualification.json) binds the exact baseline and
corrected test-file hashes to the recorded failures and two completed unfiltered
root Cargo binaries. Apple Silicon reported 12408 passed, zero failed and
36 ignored; Linux Intel reported 13330 passed, zero failed and 82 ignored.
Both manifests contain the exact corrected test file, and both logs explicitly
show all three previously failing tests passing. These are frozen combined
source qualifications, before subsequent Intel and remote Windows changes;
they do not qualify the entire present checkout. The build directories and
executables used for those runs have already been removed.

| ID | Assumption | Dependent result | Stress test / falsification probe | Status |
|---|---|---|---|---|
| A1 | `alpha.txt` uniquely identifies the fixture entry | Cursor sharing and failure non-consumption checks | First query succeeds, duplicate reaches EOF, independent open succeeds across existing ABI/service loops | Confirmed on the recorded runs |
| A2 | Independent opens on an unchanged fixture expose the same first entry during a test | No-update cursor comparison | Compare independent and normal scans on Linux and Apple Silicon; any different result fails | Confirmed on the recorded runs |

High impact for validation: host-order assumptions caused unrelated root-gate
failures. The remaining backend, checkpoint, SMP and FP requirements stay open.
Production code and unrelated pending changes are outside this group.
