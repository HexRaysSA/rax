# Rust references for bare-metal vector probes

Retrieved on 2026-09-08 from the Rust project's canonical documentation.
The HTML files are unmodified source snapshots; their relative stylesheet and
navigation assets are not mirrored. The Rust documentation is distributed under
the MIT or Apache-2.0 license. Copies of both license texts are retained here.

| Local document | Canonical title and issuer | Revision | Source URL |
|---|---|---|---|
| `rust-x86-softfloat-sse.html` | `X86_SOFTFLOAT_SSE`, Rust compiler developers | 1.100.0-nightly, documentation build `5a2be9f5f` (2026-09-06) | <https://doc.rust-lang.org/nightly/nightly-rustc/rustc_lint/builtin/static.X86_SOFTFLOAT_SSE.html> |
| `rust-inline-assembly.html` | *The Rust Reference*, “Inline assembly”, Rust project | Nightly documentation retrieved 2026-09-08; page revision not displayed | <https://doc.rust-lang.org/nightly/reference/inline-assembly.html> |
| `rust-x86_64-unknown-none.html` | *The rustc book*, “x86_64-unknown-none”, Rust project | Nightly documentation retrieved 2026-09-08; page revision not displayed | <https://doc.rust-lang.org/nightly/rustc/platform-support/x86_64-unknown-none.html> |
| `LICENSE-MIT` | Rust project MIT license | Rust compiler commit `f248f4038796913873f11ca65b1b901e311c8dae` | <https://raw.githubusercontent.com/rust-lang/rust/f248f4038796913873f11ca65b1b901e311c8dae/LICENSE-MIT> |
| `LICENSE-APACHE` | Apache License, Version 2.0 | Rust compiler commit `f248f4038796913873f11ca65b1b901e311c8dae` | <https://raw.githubusercontent.com/rust-lang/rust/f248f4038796913873f11ca65b1b901e311c8dae/LICENSE-APACHE> |

The target page describes additional target features in general terms. The
specific `x86_softfloat_sse` diagnostic and the reproduced compiler behavior
exclude enabling SSE or its implied features while retaining soft-float.
Consequently the microkernel vector probes retain the target baseline and pass
only pointers through general-purpose asm operands. Explicit discarded register
outputs describe scratch state without Rust SIMD-value operands.

Relevant Rust Reference anchors:

- `asm.operand-type.supported-operands.out`: discarded outputs declare clobbers.
- `asm.register-operands.value-type-constraints`: SIMD-value register operands
  have target-feature requirements.
- `asm.rules.reg-not-output`: unspecified output registers must be preserved.
- `asm.rules.mem-same-as-ffi`: memory accesses obey the usual FFI access rules.
- `asm.rules.preserved-registers`: x86 `preserves_flags` also covers MXCSR
  exception status; the floating-point probes therefore omit that option.

The compiler invocation used for the red-green reproduction was:

```sh
cd microkernel
cargo +nightly build --locked --release --target x86_64-unknown-none \
  -Z build-std=core,compiler_builtins \
  -Z build-std-features=compiler-builtins-mem
```

Local compiler: `rustc 1.100.0-nightly (f248f4038 2026-09-05)`,
host `aarch64-apple-darwin`, LLVM `23.1.1`.

At parent revision `db124b723b343f0fe7dfe04ddf10e12ed11fc9c4`, compilation
failed with `x86_softfloat_sse` at all three AVX/AVX2/AVX-512F attributes in
`microkernel/src/arch.rs`. Removing those attributes while retaining the
instructions and adding explicit vector scratch outputs made the same command
complete successfully. The existing all-architecture build and
`microkernel_multiarch` boot gate remain the executable regression coverage.

SHA-256 checksums of the unmodified retrieved files:

```text
f778d7368a1dc57c39b4e524acc5e1cb516fec66f3405d9c7b684936f3397090  rust-x86-softfloat-sse.html
f88f9642e88caba5414ea70c778541149eaa837393d27a9be53d579889bd4aa4  rust-inline-assembly.html
e3c8e815a3df28f3524fd0e345a5e9726d659770b976695ca86e543c28548ebd  rust-x86_64-unknown-none.html
b71bd43a069ca0641a9ecfe585ca7b3c53b5cc1608f8b68321168698e28b5ea1  LICENSE-MIT
62c7a1e35f56406896d7aa7ca52d0cc0d272ac022b5d2796e7d6905db8a3636a  LICENSE-APACHE
```
