#!/usr/bin/env python3
"""Generate the Darwin personality's ABI tables from vendored XNU sources.

Inputs (under docs/specifications/darwin/xnu-12377.121.6):

- bsd/kern/syscalls.master  -- BSD system calls, preprocessed with the macOS
  release configuration (config/MASTER, MASTER.x86_64, MASTER.arm64.MacOSX);
- osfmk/kern/syscall_sw.c   -- the Mach trap table for LP64 kernels;
- bsd/sys/errno.h           -- error numbers;
- osfmk/mach/kern_return.h, osfmk/mach/message.h (the mach_msg_return_t
  block from MACH_MSG_SUCCESS on), osfmk/mach/mig_errors.h -- Mach return
  codes.

Outputs (overwritten): src/user/darwin/abi/tables.rs and
src/user/darwin/mach/kr.rs. With --check, nothing is written and the script
fails if either file differs from what it would write.

The return-type classification follows bsd/kern/makesyscalls.sh; an entry
whose files keyword is not ALL becomes nosys, as there.
"""

import os
import re
import subprocess
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
XNU = os.path.join(ROOT, "docs/specifications/darwin/xnu-12377.121.6")
OUT = os.path.join(ROOT, "src/user/darwin/abi/tables.rs")
KR_OUT = os.path.join(ROOT, "src/user/darwin/mach/kr.rs")

# Preprocessor symbols defined for a macOS RELEASE kernel on both machines.
# CONFIG_VFORK is defined nowhere in the tree, CONFIG_EMBEDDED only for
# embedded configurations; __LP64__ and __arm64__ select the LP64 trap table.
DEFINED = {
    "SOCKETS", "SYSV_MSG", "NFSSERVER", "NECP", "CONFIG_COALITIONS",
    "SYSV_SHM", "SYSV_SEM", "PSYNCH", "CONFIG_MEMORYSTATUS", "CONFIG_MACF",
    "SKYWALK", "SENDFILE", "PGO", "NETWORKING", "CONFIG_TELEMETRY",
    "CONFIG_PROC_UUID_POLICY", "CONFIG_PERSONAS", "CONFIG_EXT_RESOLVER",
    "CONFIG_CSR", "CONFIG_CODE_DECRYPTION", "__LP64__", "__arm64__",
}

RET_TYPES = {
    "user_addr_t": "Addr",
    "user_ssize_t": "SSize",
    "user_size_t": "Size",
    "int": "Int",
    "u_int": "UInt",
    "mach_port_name_t": "UInt",
    "uint32_t": "UInt",
    "uint64_t": "U64",
    "off_t": "Off",
    "void": "None",
}


def condition(expr):
    expr = re.sub(r"/\*.*?\*/", "", expr).strip()
    m = re.fullmatch(r"defined\s*\(\s*(\w+)\s*\)\s*\|\|\s*defined\s*\(\s*(\w+)\s*\)", expr)
    if m:
        return m.group(1) in DEFINED or m.group(2) in DEFINED
    m = re.fullmatch(r"(\w+)", expr)
    if m:
        return m.group(1) in DEFINED
    raise SystemExit(f"unsupported #if expression: {expr!r}")


def preprocess(lines):
    """Yields the lines the macOS configuration keeps."""
    stack = []  # (taking, any_taken)
    for line in lines:
        s = line.strip()
        if s.startswith("#if ") or s.startswith("#ifdef "):
            parent = all(t for t, _ in stack)
            c = condition(s.split(None, 1)[1])
            stack.append((parent and c, c))
            continue
        if s.startswith("#ifndef "):
            parent = all(t for t, _ in stack)
            c = not condition(s.split(None, 1)[1])
            stack.append((parent and c, c))
            continue
        if s.startswith("#else"):
            taking, taken = stack.pop()
            parent = all(t for t, _ in stack)
            stack.append((parent and not taken, True))
            continue
        if s.startswith("#endif"):
            stack.pop()
            continue
        if s.startswith("#"):
            continue
        if all(t for t, _ in stack):
            yield line


def parse_syscalls():
    path = os.path.join(XNU, "bsd/kern/syscalls.master")
    with open(path) as f:
        lines = list(preprocess(f.read().splitlines()))
    table = {}
    for line in lines:
        if not re.match(r"^\d", line):
            continue
        m = re.match(r"^(\d+)\s+(\S+)\s+(\S+)\s*\{(.*?)\}", line)
        if not m:
            raise SystemExit(f"cannot parse: {line}")
        num = int(m.group(1))
        files = m.group(3)
        proto = m.group(2 + 2).strip().rstrip(";").strip()
        proto = proto.replace("NO_SYSCALL_STUB", "").strip()
        pm = re.match(r"^(\w+)\s+(\w+)\s*\((.*)\)$", proto)
        if not pm:
            raise SystemExit(f"cannot parse prototype: {proto}")
        ret, name, args = pm.group(1), pm.group(2), pm.group(3).strip()
        nargs = 0 if args in ("", "void") else len(args.split(","))
        if num in table:
            raise SystemExit(f"syscall {num} defined twice after preprocessing")
        if files != "ALL":
            kind, rt, n = "Nosys", "None", 0
        elif name == "nosys":
            kind, rt, n = "Nosys", "None", 0
        elif name == "enosys":
            kind, rt, n = "Enosys", "None", 0
        else:
            kind, rt, n = "Call", RET_TYPES[ret], nargs
        display = name[4:] if name.startswith("sys_") else name
        table[num] = (display, kind, rt, n)
    count = max(table) + 1
    for i in range(count):
        if i not in table:
            raise SystemExit(f"syscall {i} missing")
    return [table[i] for i in range(count)]


def parse_traps():
    path = os.path.join(XNU, "osfmk/kern/syscall_sw.c")
    with open(path) as f:
        text = f.read()
    start = re.search(r"const mach_trap_t\s+mach_trap_table", text).start()
    end = text.index("};", start)
    body = text[start:end].splitlines()[1:]
    traps = []
    for line in preprocess(body):
        m = re.search(r"/\*\s*(\d+)\s*\*/\s*MACH_TRAP\((\w+),\s*(\d+),\s*(\d+),\s*(\w+)(.*)\)", line)
        if not m:
            continue
        num = int(m.group(1))
        if num != len(traps):
            raise SystemExit(f"trap {num} out of order")
        returns_port = "mach_trap_returns_port = 1" in m.group(6)
        traps.append((m.group(2), int(m.group(3)), returns_port))
    return traps


def parse_errno():
    path = os.path.join(XNU, "bsd/sys/errno.h")
    out = {}
    with open(path) as f:
        for line in f:
            m = re.match(r"#define\s+(E[A-Z0-9]+)\s+(\d+)\s*(?:/\*\s*(.*?)\s*\*/)?", line)
            if m:
                name, num = m.group(1), int(m.group(2))
                msg = (m.group(3) or "").strip()
                if name not in out:
                    out[name] = (num, msg)
    return out


def parse_kern_returns():
    """(name, value) of every KERN_*, mach_msg return code, and MIG_* error,
    in header order."""
    out = []
    define = re.compile(r"#define\s+(\w+)\s+\(?(-?(?:0x[0-9a-fA-F]+|\d+))\)?\s*(?:/\*.*)?$")
    with open(os.path.join(XNU, "osfmk/mach/kern_return.h")) as f:
        for line in f:
            m = define.match(line.strip())
            if m and m.group(1).startswith("KERN_"):
                out.append((m.group(1), int(m.group(2), 0)))
    started = False
    with open(os.path.join(XNU, "osfmk/mach/message.h")) as f:
        for line in f:
            m = define.match(line.strip())
            if not m:
                continue
            if m.group(1) == "MACH_MSG_SUCCESS":
                started = True
            if started and re.match(r"MACH_(MSG|SEND|RCV)_", m.group(1)):
                out.append((m.group(1), int(m.group(2), 0)))
    with open(os.path.join(XNU, "osfmk/mach/mig_errors.h")) as f:
        for line in f:
            m = define.match(line.strip())
            if m and m.group(1).startswith("MIG_"):
                out.append((m.group(1), int(m.group(2), 0)))
    names = [n for n, _ in out]
    if len(names) != len(set(names)):
        raise SystemExit("duplicate return-code names")
    return out


def kern_returns_source():
    codes = parse_kern_returns()
    o = [
        "// @generated by tools/darwin/gen_abi.py from XNU 12377.121.6",
        "// (docs/specifications/darwin/xnu-12377.121.6). Do not edit by hand.",
        "",
        "//! `kern_return_t` values (`osfmk/mach/kern_return.h`), the `mach_msg`",
        "//! return codes (`osfmk/mach/message.h`), and the MIG errors",
        "//! (`osfmk/mach/mig_errors.h`).",
        "",
        "/// A `kern_return_t` or `mach_msg_return_t`.",
        "pub type KernReturn = i32;",
        "",
    ]
    for name, value in codes:
        v = f"{value:#x}" if value > 0xffff else str(value)
        o.append(f"/// `{name}`.")
        o.append(f"pub const {name}: KernReturn = {v};")
    o.append("")
    o.append("/// Every return code's name by value (the first name of a value wins).")
    o.append(f"pub static NAMES: [(KernReturn, &str); {len(codes)}] = [")
    for name, value in codes:
        v = f"{value:#x}" if value > 0xffff else str(value)
        o.append(f'    ({v}, "{name}"),')
    o.append("];")
    o.append("")
    o.append("/// The name of return code `kr`.")
    o.append("pub fn name(kr: KernReturn) -> Option<&'static str> {")
    o.append("    NAMES.iter().find(|e| e.0 == kr).map(|e| e.1)")
    o.append("}")
    o.append("")
    return "\n".join(o)


def rustfmt(text):
    """`text` as rustfmt (edition 2024) formats it, so that the checked-in
    files are both generated and formatted."""
    return subprocess.run(
        ["rustfmt", "--edition", "2024", "--emit", "stdout"],
        input=text, capture_output=True, text=True, check=True,
    ).stdout


def emit(path, text, check):
    """Writes `text` (formatted) to `path`, or with `check` verifies the
    file holds it."""
    text = rustfmt(text)
    if check:
        with open(path) as f:
            if f.read() != text:
                raise SystemExit(f"{path} is stale: run tools/darwin/{os.path.basename(__file__)}")
        return
    with open(path, "w") as f:
        f.write(text)


def main():
    syscalls = parse_syscalls()
    traps = parse_traps()
    errnos = parse_errno()
    o = []
    w = o.append
    w("// @generated by tools/darwin/gen_abi.py from XNU 12377.121.6")
    w("// (docs/specifications/darwin/xnu-12377.121.6). Do not edit by hand.")
    w("")
    w("//! Darwin system-call, Mach-trap, and error-number tables.")
    w("")
    w("use super::{BsdSyscall, Kind, MachTrap, Ret};")
    w("")
    w(f"/// The BSD system-call table (`sysent`), indexed by number.")
    w(f"pub static BSD_SYSCALLS: [BsdSyscall; {len(syscalls)}] = [")
    for i, (name, kind, rt, n) in enumerate(syscalls):
        w(f"    BsdSyscall {{ name: {name!r}, kind: Kind::{kind}, ret: Ret::{rt}, nargs: {n} }}, // {i}"
          .replace("'", '"'))
    w("];")
    w("")
    w("/// BSD system-call numbers.")
    w("pub mod nr {")
    seen = set()
    for i, (name, kind, rt, n) in enumerate(syscalls):
        if kind != "Call":
            continue
        const = name.lstrip("_").upper()
        if const in seen:
            raise SystemExit(f"duplicate constant {const}")
        seen.add(const)
        w(f"    /// `{name}`.")
        w(f"    pub const {const}: u32 = {i};")
    w("}")
    w("")
    w(f"/// The Mach trap table (`mach_trap_table`), indexed by trap number.")
    w(f"pub static MACH_TRAPS: [MachTrap; {len(traps)}] = [")
    for i, (name, nargs, rp) in enumerate(traps):
        w(f'    MachTrap {{ name: "{name}", nargs: {nargs}, returns_port: {str(rp).lower()} }}, // {i}')
    w("];")
    w("")
    w("/// Mach trap numbers.")
    w("pub mod trap {")
    seen = set()
    for i, (name, nargs, rp) in enumerate(traps):
        if name == "kern_invalid":
            continue
        const = name.lstrip("_").upper()
        if const in seen:
            continue
        seen.add(const)
        w(f"    /// `{name}`.")
        w(f"    pub const {const}: u32 = {i};")
    w("}")
    w("")
    w("/// Error numbers (`bsd/sys/errno.h`): name, number, description.")
    w("pub static ERRNO_TABLE: &[(&str, i32, &str)] = &[")
    for name, (num, msg) in sorted(errnos.items(), key=lambda kv: (kv[1][0], kv[0])):
        msg = msg.replace("\\", "\\\\").replace('"', '\\"')
        w(f'    ("{name}", {num}, "{msg}"),')
    w("];")
    w("")
    check = "--check" in sys.argv[1:]
    emit(OUT, "\n".join(o), check)
    emit(KR_OUT, kern_returns_source(), check)
    print(f"{OUT}: {len(syscalls)} syscalls, {len(traps)} traps, {len(errnos)} errnos"
          + (" (checked)" if check else ""))


if __name__ == "__main__":
    sys.exit(main())
