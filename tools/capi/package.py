#!/usr/bin/env python3
"""Build, relocate, exercise and archive a native C API SDK (Python >= 3.11)."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import subprocess
import tomllib

ROOT = Path(__file__).resolve().parents[2]
TARGETS = {
    "x86_64-unknown-linux-gnu": "x86-64",
    "aarch64-unknown-linux-gnu": "generic",
    "x86_64-apple-darwin": "x86-64",
    "aarch64-apple-darwin": "generic",
    "x86_64-pc-windows-msvc": "x86-64",
}


def run(*args, env=None):
    print("+", " ".join(map(str, args)), flush=True)
    subprocess.run(list(map(str, args)), cwd=ROOT, env=env, check=True)


def output(*args):
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()


def validate_tag(tag, version):
    # Cargo validates the package version; restrict the tag to that exact version.
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?", tag):
        raise ValueError("release tags must be vMAJOR.MINOR.PATCH[-PRERELEASE]")
    if tag != f"v{version}":
        raise ValueError(f"tag {tag!r} must match capi/Cargo.toml version v{version}")


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", choices=TARGETS, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--tag")
    args = parser.parse_args()
    version = tomllib.loads((ROOT / "capi/Cargo.toml").read_text())["package"]["version"]
    if args.tag:
        validate_tag(args.tag, version)
    rustc = output("rustc", "-vV")
    host = re.search(r"^host: (.+)$", rustc, re.M).group(1)
    if host != args.target:
        raise ValueError(f"native execution required: rustc host {host} != {args.target}")
    work = args.work_dir.resolve()
    work.mkdir(parents=True, exist_ok=False)  # Never replace an earlier/user-owned SDK.
    dist = args.output_dir.resolve()
    dist.mkdir(parents=True, exist_ok=True)
    name = f"rax-capi-{version}-{args.target}"
    archive_base = dist / name
    if any(dist.glob(name + ".*")):
        raise FileExistsError(f"archive already exists: {archive_base}")
    env = os.environ.copy()
    env.pop("CARGO_ENCODED_RUSTFLAGS", None)
    env["RUSTFLAGS"] = f"-C target-cpu={TARGETS[args.target]}"
    env["CARGO_INCREMENTAL"] = "0"
    if "apple" in args.target:
        env["MACOSX_DEPLOYMENT_TARGET"] = "11.0"
    if "msvc" not in args.target:
        env["CFLAGS"] = "-march=x86-64 -mtune=generic" if args.target.startswith("x86_64") else "-march=armv8-a"
    build = work / "build"
    original = work / "original-prefix"
    run("cmake", "-S", ROOT / "capi", "-B", build,
        f"-DCMAKE_INSTALL_PREFIX={original}", "-DCMAKE_INSTALL_LIBDIR=lib",
        f"-DRAX_CARGO_TARGET={args.target}", env=env)
    run("cmake", "--build", build, "--config", "Release", env=env)
    env["CARGO_TARGET_DIR"] = str(build / "cargo")
    run("cargo", "test", "--locked", "-p", "rax-capi", "--release", "--target", args.target,
        "--", "--test-threads=1", env=env)
    run("cmake", "--install", build, "--config", "Release", env=env)
    sdk = work / "relocated SDK" / name
    sdk.parent.mkdir()
    shutil.move(str(original), sdk)
    # Eliminate the original libraries as a possible loader fallback.
    native = build / "cargo" / args.target / "release"
    hidden_native = native.with_name("release-hidden")
    native.rename(hidden_native)
    consumer = work / "consumer"
    try:
        run("cmake", "-S", ROOT / "capi/tests/consumer", "-B", consumer,
            f"-DCMAKE_PREFIX_PATH={sdk}", env=env)
        run("cmake", "--build", consumer, "--config", "Release", env=env)
        run("ctest", "--test-dir", consumer, "-C", "Release", "--output-on-failure", env=env)
        if "windows" not in args.target:
            pc_env = env | {"PKG_CONFIG_PATH": str(sdk / "lib/pkgconfig")}
            for linkage in ("shared", "static"):
                flags = shlex.split(subprocess.check_output(
                    ["pkg-config", "--cflags", "--libs", *(["--static"] if linkage == "static" else []), "rax"],
                    env=pc_env, text=True))
                if linkage == "static":
                    flags = [str(sdk / "lib/librax.a") if flag == "-lrax" else flag for flag in flags]
                executable = work / f"pkgconfig-{linkage}"
                run("cc", ROOT / "capi/examples/x86_64_basic.c", *flags,
                    f"-Wl,-rpath,{sdk / 'lib'}", "-o", executable, env=pc_env)
                run(executable, env=pc_env)
    finally:
        hidden_native.rename(native)
    # Capture loader dependencies as part of the SDK's build provenance.
    if "apple" in args.target:
        dependencies = output("otool", "-L", str(sdk / "lib/librax.dylib"))
        if "@rpath/librax.dylib" not in dependencies:
            raise RuntimeError("dylib lacks a relocatable install name")
    elif "linux" in args.target:
        dependencies = output("readelf", "-d", str(sdk / "lib/librax.so"))
        dependencies += "\n" + output("readelf", "--version-info", str(sdk / "lib/librax.so"))
    else:
        compiler = Path((build / "rax-native-toolchain.txt").read_text().splitlines()[0])
        dependencies = output(str(compiler.with_name("dumpbin.exe")), "/DEPENDENTS", str(sdk / "bin/rax.dll"))
    shutil.copy2(ROOT / "capi/README.md", sdk / "README.md")
    manifest = {
        "package_version": version, "tag": args.tag,
        "abi_version": ".".join(re.search(rf"#define RAX_API_{part} ([0-9]+)u", (ROOT / "capi/include/rax.h").read_text()).group(1)
                                for part in ("MAJOR", "MINOR", "PATCH")),
        "commit": output("git", "rev-parse", "HEAD"), "target": args.target,
        "features": [], "profile": "release", "panic": "unwind",
        "rustc": rustc, "rustflags": env["RUSTFLAGS"], "cflags": env.get("CFLAGS", ""),
        "native_compiler": (build / "rax-native-toolchain.txt").read_text().splitlines(),
        "build_os": platform.platform(), "macos_deployment_target": env.get("MACOSX_DEPLOYMENT_TARGET"),
        "cargo_lock_sha256": digest(ROOT / "Cargo.lock"), "dependencies": dependencies,
        "validation": ["cargo test -p rax-capi --release", "relocated C/C++ shared/static consumers"],
    }
    (sdk / "build-info.json").write_text(json.dumps(manifest, indent=2) + "\n")
    files = sorted(path for path in sdk.rglob("*") if path.is_file())
    (sdk / "SHA256SUMS").write_text("".join(f"{digest(p)}  {p.relative_to(sdk).as_posix()}\n" for p in files))
    archive = Path(shutil.make_archive(str(archive_base), "zip" if "windows" in args.target else "gztar",
                                       root_dir=sdk.parent, base_dir=sdk.name))
    archive.with_name(archive.name + ".sha256").write_text(f"{digest(archive)}  {archive.name}\n")
    print(f"Validated SDK: {archive}")


if __name__ == "__main__":
    main()
