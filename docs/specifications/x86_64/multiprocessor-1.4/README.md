# Intel MultiProcessor Specification 1.4

Intel Corporation, May 1997, order242016-006. `provenance.json` identifies the
Intel-authored PDF hosted by MIT CSAIL, its retrieval time and SHA-256.

The PDF's notice permits copying for internal use only. The local reference
`24201606.pdf` is excluded from Git; this directory publishes its provenance.

Relevant sections are3.6.6 (local and I/O APIC identifiers),4.1 (floating
pointer),4.2 (configuration header),4.3.1 (CPU records),4.3.2 (bus records),
4.3.3 (I/O APIC records) and4.3.4/4.3.5 (interrupt connections). The explicit
configuration table permits the installed CPU count; the predefined default
configurations describe fixed two-processor systems.

Retrieve the local reference from the recorded source:

```sh
curl -fL 'https://pdos.csail.mit.edu/6.828/2018/readings/ia32/MPspec.pdf' -o docs/specifications/x86_64/multiprocessor-1.4/24201606.pdf
shasum -a 256 docs/specifications/x86_64/multiprocessor-1.4/24201606.pdf
```

Expected SHA-256:
`2d030e6045895b3e1fb0fee5775a8025a1f76d7c97b29437fe4783d9ef4981cc`.
