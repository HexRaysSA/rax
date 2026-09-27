# Cortex-M4 differential oracle

`qemu_oracle.py` runs the Thumb corpus of `corpus.py` on QEMU's Cortex-M4
(`qemu-system-arm -M mps2-an386`) and records each case's post-state in
`tests/generated/cortex_m/thumb_oracle.json`, which
`src/backend/emulator/cortex_m_oracle_tests.rs` replays on the RAX Cortex-M
vCPU (`cargo test --lib -- backend::emulator::cortex_m`).

Each corpus entry runs from three register/flag states. A case loads R0-R12,
LR, APSR, SP, and 256-byte data and stack windows from known values, executes
its instructions, and reports the registers and the changed memory. A fault
reports CFSR, HFSR, IPSR, MSP, EXC_RETURN and the stacked frame instead. The
SVCall handler returns through `bx lr`, `pop {pc}` or `ldr pc`.

Regenerate after editing the corpus:

```sh
LLVM_BIN=/path/to/llvm/bin python3 tools/cortex-m-diff/qemu_oracle.py \
    tests/generated/cortex_m/thumb_oracle.json
```

and update the SHA-256 in `tests/generated/manifest.toml`. The checked-in
output came from QEMU 11.1.1 and LLVM 23.1.1 (`llvm-mc`, `llvm-objcopy`,
`llvm-nm`); the script needs no linker.

Known oracle deviation: QEMU escalates a BKPT to HardFault with HFSR.FORCED,
where the Armv7-M ARM (DDI 0403E.e, B3.2.16 and C1.5) specifies
HFSR.DEBUGEVT; the replay expects DEBUGEVT.
