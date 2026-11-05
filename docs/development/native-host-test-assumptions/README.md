# Native host assumptions in checkpoint validation

The earlier native root-library run reported 13,186 passes, four failures and
26 ignored tests. All four failures reproduce individually using the immutable
Cargo-built unit executable. The retained `observations/` records include the
exact commands, executable identity and original errors.

Independent host syscalls on Linux 6.8.0-138 show:

| Test assumption | Direct host result | Fixture correction |
|---|---|---|
| A socket fills before 16 MiB | 32,804,544 bytes accepted; send-buffer default 33,554,432 bytes | Request a 4096-byte send buffer on the owned test socket |
| Queued Mach replies necessarily block before serving another request | The default socket can hold the entire queued reply workload | Bound that test connection's send buffer explicitly |
| IPv6 dump completion shares the last address datagram | `NLMSG_DONE` arrives alone | Check one final completion; retain selected emulated-profile packing checks |
| Netlink group 39 exists on the host | Groups 37 through 40 return `EINVAL`; group 33 succeeds | Use group 33 for the second bitmap word; retain emulated-profile boundary checks |

The bounded socket reports an 8192-byte send buffer and reaches `EAGAIN` after
8064 queued bytes. The test requests the buffer size rather than changing host
sysctls. `probe-host.py` reproduces the native controls with owned sockets only.
The Linux v6.8 sources and their URLs, licenses and checksums are under
`references/`. Existing Linux 6.19 emulation references remain authoritative for
the selected non-Linux netlink profile.

The independent macOS control reports an 8192-byte default send buffer and
a 4096-byte buffer after the same request. It exercises native sockets only;
it does not establish execution of the non-Linux RAX netlink tests.

The changed sources affect tests only. Complete targeted namespaces passed:
readiness 9, netlink 10, and remote Mach backpressure 13; zero failures or ignored
cases in those namespaces. Other root tests were filtered for these diagnostic
runs. Later full unfiltered libraries passed on their recorded combined sources:
Apple Silicon 12408 passed, zero failed, 36 ignored; Linux Intel 13330 passed,
zero failed, 82 ignored. The source fingerprints and command receipts are in
[qualification.json](qualification.json). These results are not an isolated
validation of current master after later Intel and remote Windows changes, and
do not establish completion of the four audit findings.

| Assumption | Probe | Status |
|---|---|---|
| Host buffer defaults explain the two backpressure failures | Reproduce the original failures; independently measure capacity; run the corrected namespaces | Confirmed on the recorded Linux host |
| Native netlink framing and membership depend on the host kernel | Compare actual host syscalls and Linux v6.8 primary sources | Confirmed on the recorded Linux host |
| The existing emulated netlink profile retains its selected behavior | Keep its group-39/group-40 and datagram-packing assertions; run on a non-Linux host | Passed within the recorded Apple Silicon complete root |

Bounded-scope finding: **high impact for validation**, because these assumptions
prevent a green native root-library gate. They do not demonstrate a defect in
RAX's production socket forwarding. No production behavior was changed here.

Three Darwin FIFO tests also enter the existing isolated executable helper
before creating their descriptors. This keeps unrelated concurrent test forks
from retaining a fixture writer while it checks EOF. The six-case FIFO namespace
passed, followed by the complete Apple Silicon root above. All original FIFO
assertions remain. The earlier interrupted root is retained; it is not relabeled
as a pass. This fixture isolation is not qualified by the Linux source, where
its earlier FIFO test file differs.

The [directory cursor fixture correction](directory-cursor.md) separately removes
three assumptions that a host directory scan returns `"."` first. It retains
the existing cursor ownership, filter, error and publication assertions, with
the same corrected source present in both complete frozen root qualifications.
