# Native Darwin tracing-policy observations

`observe_trace_policy.py` records native `PT_TRACE_ME` admission and code-signing
flag transitions independently of a Rust build. It compiles the existing
`ptrace_cs_trace.c` and `ptrace_restrict.c` fixtures for arm64 and x86-64, using
the same compiler and signing options as `tests/suites/user/darwin/fixtures.rs`.
The 16 observations cover linker/ad-hoc/runtime/get-task-allow signing and
runtime or initial restriction. Rosetta must already be available.

From the repository root on macOS:

```sh
python3 -B -m unittest discover -s tools/darwin -p test_observe_trace_policy.py
python3 -B tools/darwin/observe_trace_policy.py --output target/trace-policy-observation
```

The output directory must be new and inside this repository. The script prints
the complete JSON report, preserves it as `report.json`, and writes
`observations.zip` with the fixture sources and a SHA-256/length manifest. It
verifies every archive member before removing its compiler scratch directory.
CI also retains that archive as `darwin-trace-policy` and prints a compact
summary first so log-reader truncation cannot hide the later cases.
It records image hashes and Mach-O CPU types, raw command results, separate
mark/trace `errno` values, numeric credentials, OS/kernel/SDK/compiler versions,
CSR calls, SIP status, and available boot-argument/MAC-enforcement observations.
Missing metadata is recorded as an error, rather than interpreted as zero.
No host policy is changed. All fixture subprocesses are owned and reaped by the
script. A timeout is 120 s per command and fails collection.

Exit status 0 means all native cases were collected, including legitimate
`EPERM` observations. It does not mean tracing was allowed. Status 1 means
collection failed; the report and archive retain the available evidence.
Status 2 explicitly reports that native macOS APIs are unavailable on another
operating system. Parser/provenance unit tests run on all three operating
systems. The standalone CI workflow uses the same `xcode-27` runner label as
the required native Darwin comparison job, and prints results without waiting
for the full Rust test binary to finish.

Assumption D2: differing CI/local results may reflect native policy/context.
The falsification probe is a repeated observation with matching image,
credentials, OS, and measured policy inputs that still produces inconsistent
results. These observations do not establish that a particular CSR flag owns
the decision: XNU's `PT_TRACE_ME` and `cs_allow_invalid` paths call MACF policy
hooks. The repository's XNU 12377 reference is older than the macOS 27 kernel;
native observations remain necessary. See Apple's primary sources:
[mach_process.c](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/kern/mach_process.c),
[kern_cs.c](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/kern/kern_cs.c),
and [csr.h](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/sys/csr.h).

This tool changes no runtime predicate, public ABI, fixture assertion, or test
selection. A native policy observation is evidence for choosing a model; it is
not qualification of a subsequent emulator change.
