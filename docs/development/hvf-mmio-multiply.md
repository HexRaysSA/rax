# Implicit MUL and IMUL on Intel HVF MMIO

Legacy one-operand `MUL` and `IMUL` accept a translated MMIO read of 1, 2, 4,
or 8 bytes. The pending descriptor retains the input accumulator, the high
destination register when used, and the incoming flags. Completion publishes
the full product and CF/OF before advancing RIP. The byte form stores both
product halves in AX. Wider forms write DX:AX, EDX:EAX, or RDX:RAX. The
portable tests also check exact reply width and retained upper register bits.
[Intel SDM 086, Vol. 2A IMUL and Vol. 2B MUL](../specifications/x86_64/325462-sdm-vol-1-2abcd-3abcd-4-1.pdf)

The portable pre-fix test failed while planning the first valid device read.
All 101 portable MMIO cases passed after the repair. The native workflow ran
all 32 cases on a virtualized Intel host with macOS 15.7.9 and SDK 15.5 at
commit `f7c52c3e3459d6ab9be3391bd51cb15c7e66f570`. It compared the guest result
registers and defined flags against Intel instructions executed directly by
the host. The matrix varies width, signedness, overflow and restoration of
the pending read into a fresh vCPU. Artifact verification matched the exact
observations, executable hash and 4,821 engine input hashes.
[Native workflow](https://github.com/HexRaysSA/rax/actions/runs/44522354045)

The restoration cases cover the private CPU record. Exception-producing
division, full VM checkpoint files, and bare-metal Intel macOS execution
remain outside this qualification.
