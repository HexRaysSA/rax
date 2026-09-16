#!/usr/bin/env python3
"""Build, relocate, execute and archive a C API SDK (Python >= 3.11)."""
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

from targets import TARGETS, build_configuration

ROOT = Path(__file__).resolve().parents[2]


def run(*args, env=None):
    print("+", " ".join(map(str, args)), flush=True)
    subprocess.run(list(map(str, args)), cwd=ROOT, env=env, check=True)


def output(*args):
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()


def test_counts(stdout):
    """Reject successful Cargo invocations that did not execute the full suite."""
    summaries = re.findall(
        r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out", stdout)
    counts = [sum(int(summary[i]) for summary in summaries) for i in range(5)]
    if not counts[0] or any(counts[i] for i in (1, 2, 4)):
        raise RuntimeError(f"C API test execution incomplete: {counts}")
    return dict(zip(("passed", "failed", "ignored", "measured", "filtered"), counts))


def run_cargo_tests(*args, env):
    print("+", " ".join(map(str, args)), flush=True)
    result = subprocess.run(list(map(str, args)), cwd=ROOT, env=env, check=False,
                            stdout=subprocess.PIPE, text=True)
    print(result.stdout, end="", flush=True)
    result.check_returncode()
    return test_counts(result.stdout)


def validate_tag(tag, version):
    # Cargo validates the package version; restrict the tag to that exact version.
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?", tag):
        raise ValueError("release tags must be vMAJOR.MINOR.PATCH[-PRERELEASE]")
    if tag != f"v{version}":
        raise ValueError(f"tag {tag!r} must match capi/Cargo.toml version v{version}")


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def collect(source, destination):
    """Copy a Cargo artifact, which is uplifted as a symlink into the build tree.

    Moving the link instead would ship a dangling relative path, and nothing
    downstream reads through a broken symlink to notice.
    """
    source = source.resolve(strict=True)
    (shutil.copytree if source.is_dir() else shutil.copy2)(source, destination)


def split_debug_info(target, native, sdk, work, binutils):
    """Move the installed libraries' debug info into a sidecar bundle.

    The SDK archive keeps the stripped libraries consumers link against; the
    sidecars (.dSYM / .so.debug / .pdb) ship as a separate archive so a
    debugger or crash reporter can recover full symbols on demand. Splitting
    before the relocated consumer tests means those gates run against exactly
    the libraries the SDK archive delivers.
    """
    debug = work / "debug bundle" / (sdk.name + "-debug")
    (debug / "lib").mkdir(parents=True)
    if "apple" in target:
        # The build environment selects split-debuginfo=packed, so rustc already
        # ran dsymutil for the cdylib; the archive carries DWARF in its members.
        collect(native / "librax.dylib.dSYM", debug / "lib/librax.dylib.dSYM")
        shutil.copy2(sdk / "lib/librax.a", debug / "lib/librax.a")
        run("strip", "-x", "-S", sdk / "lib/librax.dylib")
        run("strip", "-S", sdk / "lib/librax.a")
        run("ranlib", sdk / "lib/librax.a")
    elif "windows" in target:
        # MSVC keeps debug info out of the DLL entirely; the static library's
        # CodeView records live in its own members and stay with the SDK.
        (debug / "bin").mkdir()
        pdb, = native.glob("*.pdb")  # Anything but the cdylib's PDB is a packaging bug.
        collect(pdb, debug / "bin" / pdb.name)
    else:
        objcopy, strip = binutils + "objcopy", binutils + "strip"
        shared, sidecar = sdk / "lib/librax.so", debug / "lib/librax.so.debug"
        run(objcopy, "--only-keep-debug", shared, sidecar)
        shutil.copy2(sdk / "lib/librax.a", debug / "lib/librax.a")
        run(strip, "--strip-unneeded", shared)
        # --strip-unneeded would discard the static archive's external symbols.
        run(strip, "--strip-debug", sdk / "lib/librax.a")
        # The link section records only the sidecar's base name; a debugger
        # resolves it beside the library or under .debug/.
        run(objcopy, f"--add-gnu-debuglink={sidecar}", shared)
    return debug


def seal(bundle, dist, target):
    """Checksum every file in a bundle, then archive and checksum the archive."""
    # A link would leave the archive depending on a build tree nobody receives,
    # and would be skipped by the checksum manifest rather than reported.
    links = sorted(str(path.relative_to(bundle)) for path in bundle.rglob("*") if path.is_symlink())
    if links:
        raise RuntimeError(f"{bundle.name} references paths outside the archive: {links}")
    files = sorted(path for path in bundle.rglob("*") if path.is_file())
    (bundle / "SHA256SUMS").write_text(
        "".join(f"{digest(p)}  {p.relative_to(bundle).as_posix()}\n" for p in files))
    archive = Path(shutil.make_archive(str(dist / bundle.name), "zip" if "windows" in target else "gztar",
                                       root_dir=bundle.parent, base_dir=bundle.name))
    archive.with_name(archive.name + ".sha256").write_text(f"{digest(archive)}  {archive.name}\n")
    return archive


def validate_sdk(target, work, name, env, cmake_args, runner, cc, binutils):
    """Execute the Rust suite and relocated consumers for an already-built SDK."""
    build = work / "build"
    original = work / "original-prefix"
    env["CARGO_TARGET_DIR"] = str(build / "cargo")
    counts = run_cargo_tests("cargo", "test", "--locked", "-p", "rax-capi", "--release", "--target", target,
                             "--", "--test-threads=1", env=env)
    run("cmake", "--install", build, "--config", "Release", env=env)
    sdk = work / "relocated SDK" / name
    sdk.parent.mkdir()
    shutil.move(str(original), sdk)
    native = build / "cargo" / target / "release"
    debug = split_debug_info(target, native, sdk, work, binutils)
    # Eliminate the original libraries as a possible loader fallback.
    hidden_native = native.with_name("release-hidden")
    native.rename(hidden_native)
    consumer = work / "consumer"
    try:
        run("cmake", "-S", ROOT / "capi/tests/consumer", "-B", consumer,
            f"-DCMAKE_PREFIX_PATH={sdk}", *cmake_args, env=env)
        run("cmake", "--build", consumer, "--config", "Release", env=env)
        run("ctest", "--test-dir", consumer, "-C", "Release", "--output-on-failure", "--no-tests=error", env=env)
        if "windows" not in target:
            pc_env = env | {"PKG_CONFIG_PATH": str(sdk / "lib/pkgconfig")}
            for linkage in ("shared", "static"):
                flags = shlex.split(subprocess.check_output(
                    ["pkg-config", "--cflags", "--libs", *(["--static"] if linkage == "static" else []), "rax"],
                    env=pc_env, text=True))
                if linkage == "static":
                    flags = [str(sdk / "lib/librax.a") if flag == "-lrax" else flag for flag in flags]
                executable = work / f"pkgconfig-{linkage}"
                run(cc, *shlex.split(env["CFLAGS"]), ROOT / "capi/examples/x86_64_basic.c", *flags,
                    f"-Wl,-rpath,{sdk / 'lib'}", "-o", executable, env=pc_env)
                run(*runner, executable, env=pc_env)
    finally:
        hidden_native.rename(native)
    return sdk, debug, counts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", choices=TARGETS, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--tag")
    parser.add_argument("--cross-linux", action="store_true",
                        help="cross-build and execute a registered GNU/Linux target under QEMU")
    args = parser.parse_args()
    version = tomllib.loads((ROOT / "capi/Cargo.toml").read_text())["package"]["version"]
    if args.tag:
        validate_tag(args.tag, version)
    rustc = output("rustc", "-vV")
    host = re.search(r"^host: (.+)$", rustc, re.M).group(1)
    env, cmake_args, runner, cc = build_configuration(args.target, host, args.cross_linux, os.environ)
    work = args.work_dir.resolve()
    work.mkdir(parents=True, exist_ok=False)  # Never replace an earlier/user-owned SDK.
    dist = args.output_dir.resolve()
    dist.mkdir(parents=True, exist_ok=True)
    name = f"rax-capi-{version}-{args.target}"
    if any(dist.glob(name + "*")):
        raise FileExistsError(f"archive already exists: {dist / name}")
    build = work / "build"
    original = work / "original-prefix"
    run("cmake", "-S", ROOT / "capi", "-B", build,
        f"-DCMAKE_INSTALL_PREFIX={original}", "-DCMAKE_INSTALL_LIBDIR=lib",
        f"-DRAX_CARGO_TARGET={args.target}", *cmake_args, env=env)
    run("cmake", "--build", build, "--config", "Release", env=env)
    binutils = f"{TARGETS[args.target].cross_prefix}-" if args.cross_linux else ""
    sdk, debug, counts = validate_sdk(args.target, work, name, env, cmake_args, runner, cc, binutils)
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
    manifest = {
        "package_version": version, "tag": args.tag,
        "abi_version": ".".join(re.search(rf"#define RAX_API_{part} ([0-9]+)u", (ROOT / "capi/include/rax.h").read_text()).group(1)
                                for part in ("MAJOR", "MINOR", "PATCH")),
        "commit": output("git", "rev-parse", "HEAD"), "target": args.target,
        "features": [], "profile": "release", "panic": "unwind",
        "rust_tests": counts,
        "experimental": TARGETS[args.target].experimental,
        "execution": {"kind": "qemu-user" if runner else "native", "runner": runner,
                      "rustc_host": host,
                      "runner_version": output(runner[0], "--version") if runner else None},
        "rustc": rustc, "rustflags": env["RUSTFLAGS"], "cflags": env.get("CFLAGS", ""),
        "native_compiler": (build / "rax-native-toolchain.txt").read_text().splitlines(),
        "build_os": platform.platform(), "macos_deployment_target": env.get("MACOSX_DEPLOYMENT_TARGET"),
        "build_image": env.get("SDK_BUILD_IMAGE"),
        "build_distribution": platform.freedesktop_os_release() if platform.system() == "Linux" else None,
        "cargo_lock_sha256": digest(ROOT / "Cargo.lock"), "dependencies": dependencies,
        "debug": env["CARGO_PROFILE_RELEASE_DEBUG"],
        "debug_info": sorted(p.relative_to(debug).as_posix() for d in debug.iterdir() for p in d.iterdir()),
        "validation": ["cargo test -p rax-capi --release", "relocated C/C++ shared/static consumers"],
    }
    for bundle in (sdk, debug):
        # One manifest describes both halves: they come from the same build.
        shutil.copy2(ROOT / "capi/README.md", bundle / "README.md")
        (bundle / "build-info.json").write_text(json.dumps(manifest, indent=2) + "\n")
        print(f"Validated bundle: {seal(bundle, dist, args.target)}")


if __name__ == "__main__":
    main()
