# Independent Intel SHLD/SHRD observations

The fixture records 25,344 independent RAM instructions on an Intel Xeon
E5-1650 v3 with Linux KVM. No RAX engine code is linked into the native guest
or runner. The manifest retains kernel/CPU identity, GCC/LLVM commands,
source hashes, record hashes, masks and collector cleanup status.

| File | Bytes | SHA-256 |
|---|---:|---|
| `cases.bin` | 4,359,168 | `225824a7c0b6290af75f5928ee8e0360ba8a3e129658149256590495b9b0544e` |
| `records.bin` | 4,257,812 | `bdd3818dcc9f7a258a4ec5622957658b04f0031be7cb50b7ec1071a9bffc856c` |

Binary storage is justified by complete replay of all 16 GPRs, three 8-byte
memory words and input/output flags, without rerunning a privileged oracle on
every test host. Cases occupy 172 bytes each; observations occupy 168 bytes
each plus a 20-byte header/trailer. The combined binary size is 8,616,980 bytes.
These are generated reference records, not executable guest images or RAM dumps.

The matrix covers SHLD/SHRD, memory widths 16/32/64 bits, imm8/CL, source
registers 0/1/8/15, boundary counts, six destination patterns, three source
patterns and two initial flag states. It includes source/CL aliasing.
Undefined AF/OF bits are excluded only when specified by SDM086. Undefined
16-bit masked counts 17-31 are excluded from fixed-value comparisons;
separate admission/footprint and native permission controls cover them.

On native Linux x86-64 with accessible `/dev/kvm`, GCC and LLVM tools:

```sh
python3 tools/hvf/mmio_double_shift_oracle.py \
  --repo "$PWD" --out /tmp/rax-double-shift-reference-new \
  --llvm-bin /usr/local/bin
```

The output directory must be new. Expect `25344` cases and
`native_reference_complete`. The collector removes temporary object files,
guest executables and runner builds on success or failure. Its retained output
contains the two binaries, manifest and raw tool output. `--exhaustive-counts`
checks all 256 raw counts within the defined-value domain without replacing
this boundary fixture. `--capture` writes a new fixture directory and rejects
an existing one.

The reference was independently recollected with the checked-in collector;
both binary hashes reproduced the original capture exactly. Primary sections,
the observed planner failure, permission controls, native HVF selected cases
and evidence limits are documented in
[the implementation record](../../../../docs/development/hvf-mmio-double-shifts/README.md).
