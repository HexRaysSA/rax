"""Prepared native consumer admission and diagnostic command execution."""
import codecs
import hashlib
import json
import os
from pathlib import Path
import signal
import selectors
import subprocess
import sys
import time

EXECUTABLE = "native-guest"
CONSUMER_SOURCES = ("intel_mmio_native_guest.rs", "intel_mmio_double_shift.rs",
                    "intel_mmio_guest_debug.rs", "intel_mmio_coherence.rs")


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def consumer_inputs(root):
    """Every Rust input linked into the separately compiled native consumer."""
    return {"tools/hvf/" + name: sha(root / "tools/hvf" / name)
            for name in CONSUMER_SOURCES}


def engine_inputs(root):
    files = list((root / "src").rglob("*.rs"))
    files.extend(path for path in (root / "vendor/vm-memory").rglob("*")
                 if path.is_file() and path.suffix in {".rs", ".toml"})
    files.extend(root / name for name in ("Cargo.toml", "Cargo.lock", ".cargo/config.toml")
                 if (root / name).exists())
    return {str(path.relative_to(root)): sha(path) for path in files}


def save(path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n")
    temporary.replace(path)


def execute(label, command, *, root, environment, output, result, timeout=60):
    """Supervise the owned process group and stderr with one command deadline."""
    started = time.monotonic()
    stdout, stderr = output / (label + ".stdout"), output / (label + ".stderr")
    entry = {"label": label, "argv": [str(value) for value in command]}
    result["commands"].append(entry)
    save(output / "result.json", result)
    print(json.dumps({"phase": label, "state": "started"}), file=sys.stderr, flush=True)
    with stdout.open("xb") as out, stderr.open("xb") as err:
        child = subprocess.Popen(command, cwd=root, env=environment,
                                 stdout=out, stderr=subprocess.PIPE, start_new_session=True)
        entry["pid"] = child.pid
        save(output / "result.json", result)

        os.set_blocking(child.stderr.fileno(), False)
        selector = selectors.DefaultSelector()
        selector.register(child.stderr, selectors.EVENT_READ)
        decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")

        def relay():
            data = os.read(child.stderr.fileno(), 65536)
            if not data:
                return False
            err.write(data)
            err.flush()
            print(decoder.decode(data), end="", file=sys.stderr, flush=True)
            return True

        try:
            eof = False
            while True:
                code = child.poll()
                if code is not None and eof:
                    break
                remaining = timeout - (time.monotonic() - started)
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(command, timeout)
                for _key, _events in selector.select(min(remaining, 0.1)):
                    if not relay():
                        selector.unregister(child.stderr)
                        eof = True
        except BaseException as error:
            entry.update(timed_out=isinstance(error, subprocess.TimeoutExpired),
                         error=repr(error), seconds=time.monotonic() - started)
            save(output / "result.json", result)
            # start_new_session gives this invocation a separate process group.
            # Signal only that owned group, including compiler descendants, and
            # bound reaping as well: a host SDK call may not return after a
            # termination request. Never wait for a separate stderr thread.
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                entry["reap_timed_out"] = True
            drain_deadline = time.monotonic() + 0.1
            while time.monotonic() < drain_deadline:
                try:
                    if not relay():
                        break
                except BlockingIOError:
                    break
            entry["exit_code"] = child.poll()
            entry["seconds"] = time.monotonic() - started
            save(output / "result.json", result)
            raise
        finally:
            selector.close()
            child.stderr.close()
            print(decoder.decode(b"", final=True), end="", file=sys.stderr, flush=True)
    entry.update(exit_code=code, seconds=time.monotonic() - started)
    save(output / "result.json", result)
    print(json.dumps({"phase": label, "state": "finished", "exit_code": code,
                      "seconds": entry["seconds"]}), file=sys.stderr, flush=True)
    if code:
        raise RuntimeError(f"{label} failed with status {code}")
    return stdout


def export_description(output, result, expected_cases):
    description = {"version": 2, "executable": EXECUTABLE,
                   "expected_cases": expected_cases, "support_sha256": sha(Path(__file__)),
                   **{key: result[key] for key in (
                       "executable_sha256", "engine_source_digest", "consumer_sha256",
                       "script_sha256", "libraries", "build_environment")}}
    save(output / "prepared.json", description)
    return description


def admit(directory, inputs, consumer_hash, script_hash, expected_cases):
    directory = directory.resolve()
    for name in (EXECUTABLE, "prepared.json", "engine-source.json", "result.json"):
        path = directory / name
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"prepared input must be a regular file: {name}")
    description = json.loads((directory / "prepared.json").read_text())
    if not isinstance(description, dict):
        raise ValueError("prepared description must be an object")
    if type(description["version"]) is not int or description["version"] != 2:
        raise ValueError("unknown prepared artifact version")
    if (description["executable"] != EXECUTABLE
            or type(description["expected_cases"]) is not int
            or type(expected_cases) is not int or expected_cases <= 0
            or description["expected_cases"] != expected_cases):
        raise ValueError("prepared executable or case profile differs")
    source = json.loads((directory / "engine-source.json").read_text())
    if source != inputs or description["engine_source_digest"] != digest(inputs):
        raise ValueError("prepared engine source differs from this checkout")
    if (description["consumer_sha256"] != consumer_hash
            or description["script_sha256"] != script_hash
            or description["support_sha256"] != sha(Path(__file__))):
        raise ValueError("prepared consumer or tooling differs")
    executable = directory / EXECUTABLE
    if sha(executable) != description["executable_sha256"]:
        raise ValueError("prepared executable checksum differs")
    report = json.loads((directory / "result.json").read_text())
    if (not isinstance(report, dict)
            or report.get("success") is not True or report.get("compile_only") is not True
            or report.get("export_guest") is not True or report.get("owned_build_removed") is not True
            or report.get("executable_sha256") != description["executable_sha256"]
            or report.get("engine_source_digest") != digest(inputs)):
        raise ValueError("prepared compilation did not qualify its artifact")
    return executable, description


def observations(path, expected):
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    if (type(expected) is not int or expected <= 0 or len(rows) != expected
            or any(not isinstance(row, dict)
                   or type(row.get("case")) is not int or row.get("case") != index
                   or row.get("passed") is not True for index, row in enumerate(rows))):
        raise ValueError("guest observations differ from the complete expected profile")
    return rows
