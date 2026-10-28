from pathlib import Path
import argparse, hashlib, json, os, subprocess, sys, time, traceback

p = argparse.ArgumentParser()
p.add_argument("--root", type=Path, required=True)
p.add_argument("--output", type=Path, required=True)
p.add_argument("--environment", required=True)
a = p.parse_args()
R = a.root.resolve()
O = a.output.resolve()
assert O.parent == (R / "target").resolve()
assert not (O / "receipt.json").exists()
assert sys.getwindowsversion().build == 29695
s = {
    "pid": os.getpid(),
    "created_epoch_seconds": time.time(),
    "kernel": list(sys.getwindowsversion()),
    "state": "checking",
    "commands": [],
}


def save():
    (O / "receipt.json").write_text(json.dumps(s, indent=2))


def digest(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


save()
try:
    expected = json.loads((O / "expected-sources.json").read_text())
    assert all(digest(R / n) == h for n, h in expected.items())
    before = {**expected, str(Path(__file__).resolve()): digest(Path(__file__))}
    s["sources_sha256"] = before
    save()
    tmp = O / "tmp"
    tmp.mkdir()
    env = os.environ.copy()
    env.update(
        TMPDIR=str(tmp), TMP=str(tmp), TEMP=str(tmp), PYTHONDONTWRITEBYTECODE="1"
    )
    argv = [
        sys.executable,
        "-I",
        "-B",
        str(
            R
            / "docs/specifications/windows/native-process-image-information/run-relocation-directory-v1.py"
        ),
        "--environment",
        a.environment,
        "--architectures",
        "arm64",
        "x64",
        "x86",
    ]
    started = time.monotonic()
    with (O / "observe.log").open("wb") as log, (O / "observe.err").open("wb") as err:
        child = subprocess.Popen(
            argv, cwd=R, env=env, stdin=subprocess.DEVNULL, stdout=log, stderr=err
        )
        s.update(state="native relocation controls", child_pid=child.pid)
        save()
        code = child.wait(timeout=480)
    s["commands"].append(
        {"argv": argv, "exit_code": code, "seconds": time.monotonic() - started}
    )
    save()
    assert code == 0, (O / "observe.err").read_text(errors="replace")
    rows = [json.loads(line) for line in (O / "observe.log").read_text().splitlines()]
    assert len(rows) == 15
    assert sum(r["kind"] == "metadata-baseline" for r in rows) == 3
    assert sum(r["kind"] == "section-metadata" and r["available"] for r in rows) == 10
    assert (
        sum(r["kind"] == "section-metadata" and not r["available"] for r in rows) == 2
    )
    assert all(
        (r["rows"][0] if r["kind"] == "metadata-baseline" else r["host"])["build"]
        == 29695
        for r in rows
    )
    assert all(digest(R / n) == h for n, h in before.items())
    s["records"] = rows
    s.update(state="finished", exit_code=0)
except BaseException:
    s.update(state="failed", exit_code=1, error=traceback.format_exc())
finally:
    save()
