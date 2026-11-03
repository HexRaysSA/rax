# Native I/O completion frontiers

`probe.c` uses the Linux KVM UAPI directly with one private real-mode vCPU,
2 MiB of RAM and no in-kernel IRQchip. Its observed kernel is Linux
6.8.0-138-generic on abyss. The source and terminal receipt are retained
verbatim; `manifest.json` identifies the compiler, headers and SHA-256 values.
This is an independent kernel protocol observation, not a complete RAX
checkpoint implementation.

| Operation | Input/completion | Observed immediate-exit result | Subsequent-instruction marker |
|---|---|---|---|
| Scalar `IN AL,0x70` | Supply `0x5a` | EINTR; RIP advances from `0x1000` to `0x1002`, AL becomes `0x5a` | RAM byte `0x3000` stays zero |
| Scalar `OUT 0x71,AL` | Complete the exposed output | EINTR; RIP advances from `0x1005` to `0x1007` | Following HLT is reached only on ordinary reentry |
| `INC byte [0xfee00000]` | Supply MMIO read byte `0x5a` | A second MMIO exit writes `0x5b`, although immediate exit remains set; RIP is already `0x1007` | Following HLT remains unexecuted |
| MMIO write from that `INC` | Complete the exposed write | EINTR; RIP remains `0x1007` | HLT occurs on ordinary reentry |
| REP INS, widths 1/2/4 bytes, DF=0/1 | Supply every native batch, 256 elements per case | EINTR after each batch; native RCX/RDI reflect completed progress while RIP remains `0x1000` | RAM byte `0x3000` stays zero until ordinary reentry writes `0x99` |

The reverse one-byte REP case uses two native batches: 255 elements followed
by one. Every other selected case uses one 256-element batch. All destination
bytes equal `0x5a`, in both directions. Each case then resumes to the expected
marker and HLT. These assertions distinguish native batch completion from
executing the following instruction. They also retain the native RF and RIP
values rather than synthesizing a post-instruction PC.

KVM API section 5, retained at
`../../kvm-public-state/references/kvm-api-v6.8.rst`, requires native I/O
completion before migration and describes immediate-exit completion. The
observed read-modify-write sequence shows why a producer must account for
follow-on device exits before declaring a complete CPU cut. Simply copying
public registers at the initial MMIO read or assuming that one drain call
always returns EINTR does not preserve that instruction's complete state.

The existing RAX REP metadata counterexample remains separate: it observes
native width/count being flattened into an eight-bit public size. This direct
kernel probe establishes completion behavior and does not qualify that adapter.

To reproduce on an x86-64 Linux host with accessible `/dev/kvm`:

```sh
probe_dir=$(mktemp -d /tmp/rax-native-completion.XXXXXX)
trap 'rm -f "$probe_dir/probe"; rmdir "$probe_dir"' EXIT
cc -std=gnu11 -O2 -Wall -Wextra -Werror probe.c -o "$probe_dir/probe"
timeout 20s "$probe_dir/probe"
```

Assumption N1: the kernel exposes these native batch/completion boundaries on
the recorded host. Stress probes vary scalar/RMW/REP, all three PIO widths and
both directions, and check guest memory plus GET_REGS after every drain. A
nonmatching exit, count, PC, register value or marker fails the probe. Status:
confirmed on the recorded host; other kernel/CPU profiles remain unverified.

High impact: the complete private/shared/in-flight producer must preserve the
represented device effects and CPU frontier through source-free restore.
This remains required under C-STATE.
