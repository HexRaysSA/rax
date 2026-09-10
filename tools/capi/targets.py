"""SDK target contracts shared by packaging, publication and validation."""
from dataclasses import dataclass


@dataclass(frozen=True)
class Target:
    cpu: str | None = None  # None preserves rustc's target-specific baseline.
    cflags: str = ""
    experimental: bool = False
    cross_prefix: str | None = None
    qemu: str | None = None
    processor: str | None = None


TARGETS = {
    "x86_64-unknown-linux-gnu": Target("x86-64", "-march=x86-64 -mtune=generic"),
    "aarch64-unknown-linux-gnu": Target("generic", "-march=armv8-a"),
    "x86_64-apple-darwin": Target("x86-64", "-march=x86-64 -mtune=generic"),
    "aarch64-apple-darwin": Target("generic", "-march=armv8-a"),
    "x86_64-pc-windows-msvc": Target("x86-64"),
    "aarch64-pc-windows-msvc": Target("generic", experimental=True),
    "x86_64-unknown-linux-musl": Target("x86-64", "-march=x86-64 -mtune=generic", True),
    "aarch64-unknown-linux-musl": Target("generic", "-march=armv8-a", True),
    "riscv64gc-unknown-linux-gnu": Target(
        experimental=True, cross_prefix="riscv64-linux-gnu", qemu="qemu-riscv64", processor="riscv64"),
    "powerpc64le-unknown-linux-gnu": Target(
        experimental=True, cross_prefix="powerpc64le-linux-gnu", qemu="qemu-ppc64le", processor="ppc64le"),
    "powerpc64-unknown-linux-gnu": Target(
        experimental=True, cross_prefix="powerpc64-linux-gnu", qemu="qemu-ppc64", processor="ppc64"),
    "s390x-unknown-linux-gnu": Target(
        experimental=True, cross_prefix="s390x-linux-gnu", qemu="qemu-s390x", processor="s390x"),
}


def build_configuration(target, host, cross_linux, inherited_env):
    """Select one toolchain/executor for Cargo, CMake and pkg-config consumers.

    Cross execution is explicit and restricted to the registered GNU/Linux
    sysroots supplied by Debian/Ubuntu cross-toolchain packages.
    """
    spec = TARGETS[target]
    if cross_linux:
        if "linux" not in host or not spec.cross_prefix:
            raise ValueError("--cross-linux requires a Linux host and a registered cross target")
    elif host != target:
        raise ValueError(f"native execution required: rustc host {host} != {target}; use --cross-linux for registered Linux targets")
    env = inherited_env.copy()
    env.pop("CARGO_ENCODED_RUSTFLAGS", None)
    env["RUSTFLAGS"] = f"-C target-cpu={spec.cpu}" if spec.cpu else ""
    if target.endswith("-musl"):
        # Rust's static CRT default cannot produce this SDK's cdylib. Both
        # library variants use the target's dynamic musl CRT; .a is not a
        # promise that downstream executables are fully static.
        env["RUSTFLAGS"] += " -C target-feature=-crt-static"
    env["CARGO_INCREMENTAL"] = "0"
    env["CFLAGS"] = spec.cflags
    env["CXXFLAGS"] = spec.cflags
    if "apple" in target:
        env["MACOSX_DEPLOYMENT_TARGET"] = "11.0"
    if target == "aarch64-pc-windows-msvc":
        env["CMAKE_GENERATOR_PLATFORM"] = "ARM64"
    cmake = []
    runner = []
    cc = "cc"
    if cross_linux:
        prefix = spec.cross_prefix
        cc, cxx = f"{prefix}-gcc", f"{prefix}-g++"
        runner = [spec.qemu, "-L", f"/usr/{prefix}"]
        cargo_key = target.upper().replace("-", "_")
        env[f"CARGO_TARGET_{cargo_key}_LINKER"] = cc
        env[f"CARGO_TARGET_{cargo_key}_RUNNER"] = " ".join(runner)
        # Target-qualified cc-rs settings keep host build scripts native.
        env[f"CC_{target.replace('-', '_')}"] = cc
        env[f"CXX_{target.replace('-', '_')}"] = cxx
        env[f"AR_{target.replace('-', '_')}"] = f"{prefix}-ar"
        cmake = ["-DCMAKE_SYSTEM_NAME=Linux", f"-DCMAKE_SYSTEM_PROCESSOR={spec.processor}",
                 f"-DCMAKE_C_COMPILER={cc}", f"-DCMAKE_CXX_COMPILER={cxx}",
                 f"-DCMAKE_CROSSCOMPILING_EMULATOR={';'.join(runner)}"]
    return env, cmake, runner, cc
