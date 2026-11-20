#!/usr/bin/env python3
"""Generate the Xtensa opcode recognizer from a Tensilica core configuration.

Input: the `xtensa-modules.inc.c` of a core (libisa tables, Tensilica MIT-style
notice), for example `target/xtensa/core-esp32s3/xtensa-modules.inc.c` of
Espressif's QEMU fork. Output: `src/isa/xtensa/generated/opcodes.rs`, with the
`Opcode` enum, the mnemonics, the slot decoders and the field getters they use.

The slot decoders of the tables are if/return chains over field getters; they
are translated statement by statement, so the Rust decoder recognizes exactly
the encodings the tables define.

Usage: gen_opcodes.py <xtensa-modules.inc.c> [-o <opcodes.rs>]
"""

import argparse
import pathlib
import re
import sys

SLOTS = {
    "inst": "x24",
    "inst16a": "x16a",
    "inst16b": "x16b",
    "slot_format_32_0": "f32",
}


def parse_enum(src):
    m = re.search(r"enum xtensa_opcode_id \{(.*?)\};", src, re.S)
    if not m:
        sys.exit("no `enum xtensa_opcode_id`")
    names = [n.strip().rstrip(",") for n in m.group(1).split("\n")]
    return [n[len("OPCODE_"):] for n in names if n.startswith("OPCODE_")]


def parse_mnemonics(src):
    m = re.search(r"static xtensa_opcode_internal opcodes\[\] = \{(.*?)\n\};", src, re.S)
    if not m:
        sys.exit("no `opcodes[]` table")
    return re.findall(r'\{ "([^"]+)", ICLASS_', m.group(1))


def parse_list_enum(src, name, prefix):
    m = re.search(rf"enum {name} \{{(.*?)\}};", src, re.S)
    if not m:
        sys.exit(f"no `enum {name}`")
    items = [n.strip().rstrip(",") for n in m.group(1).split("\n")]
    return [n[len(prefix):] for n in items if n.startswith(prefix)]


def parse_ar_operands(src):
    """Per opcode id, the fields of its AR register operands."""
    field_names = parse_list_enum(src, "xtensa_field_id", "FIELD_")
    getters = {}
    for slot in SLOTS:
        m = re.search(rf"Slot_{slot}_get_field_fns\[\] = \{{(.*?)\n\}};", src, re.S)
        fns = [f.strip() for f in m.group(1).replace("\n", "").split(",") if f.strip()]
        if len(fns) != len(field_names):
            sys.exit(f"slot {slot}: {len(fns)} field getters for {len(field_names)} fields")
        for name, fn in zip(field_names, fns):
            if fn == "0":
                continue
            g = re.fullmatch(rf"Field_(\w+?)_Slot_{slot}_get", fn)
            i = re.fullmatch(r"Implicit_Field_\w*?(\d+)_get", fn)
            if g:
                getters[(name, slot)] = ("field", g.group(1))
            elif i:
                getters[(name, slot)] = ("const", int(i.group(1)))
            else:
                getters[(name, slot)] = ("other", fn)
    m = re.search(r"static xtensa_operand_internal operands\[\] = \{(.*?)\n\};", src, re.S)
    operands = re.findall(r'\{ "([^"]+)", FIELD_(\w+), (REGFILE_\w+|-1), (\d+),', m.group(1))
    operand_ids = parse_list_enum(src, "xtensa_operand_id", "OPERAND_")
    if len(operands) != len(operand_ids):
        sys.exit("operand table and operand ids differ in length")
    operand = dict(zip(operand_ids, operands))
    iclass_ids = parse_list_enum(src, "xtensa_iclass_id", "ICLASS_")
    m = re.search(r"static xtensa_iclass_internal iclasses\[\] = \{(.*?)\n\};", src, re.S)
    iclass_args = re.findall(r"\{ (\d+), (Iclass_\w+_args|0)(?: /\* \w+ \*/)?,", m.group(1))
    if len(iclass_args) != len(iclass_ids):
        sys.exit("iclass table and iclass ids differ in length")
    args = {}
    for am in re.finditer(r"static xtensa_arg_internal (Iclass_\w+_args)\[\] = \{(.*?)\n\};", src, re.S):
        args[am.group(1)] = re.findall(r"\{ \{ OPERAND_(\w+) \}, '(\w)' \}", am.group(2))
    iclass = {}
    for ident, (n, arr) in zip(iclass_ids, iclass_args):
        lst = args.get(arr, []) if arr != "0" else []
        if len(lst) != int(n):
            sys.exit(f"iclass {ident}: {n} args announced, {len(lst)} found")
        iclass[ident] = lst
    m = re.search(r"static xtensa_opcode_internal opcodes\[\] = \{(.*?)\n\};", src, re.S)
    op_iclass = re.findall(r'\{ "[^"]+", ICLASS_(\w+),', m.group(1))
    result = []
    for ic in op_iclass:
        fields = []
        for name, _inout in iclass[ic]:
            _, field, regfile, nregs = operand[name]
            if regfile == "REGFILE_AR":
                if nregs != "1":
                    sys.exit(f"AR operand {name} spans {nregs} registers")
                fields.append(field)
        result.append(fields)
    return result, getters


def parse_fields(src):
    fields = {}
    pat = re.compile(
        r"^Field_(\w+?)_Slot_(inst|inst16a|inst16b|slot_format_32_0)_get "
        r"\(const xtensa_insnbuf insn\)\n\{\n(.*?)\n\}",
        re.S | re.M,
    )
    for m in pat.finditer(src):
        steps = []
        for line in m.group(3).split("\n"):
            line = line.strip()
            if line in ("unsigned tie_t = 0;", "return tie_t;", ""):
                continue
            s = re.fullmatch(
                r"tie_t = \(tie_t << (\d+)\) \| \(\(insn\[0\] << (\d+)\) >> (\d+)\);", line
            )
            if not s:
                sys.exit(f"unexpected field getter line: {line!r}")
            steps.append(tuple(int(x) for x in s.groups()))
        fields[(m.group(1), m.group(2))] = steps
    return fields


def parse_format32_slot(src):
    m = re.search(
        r"^Slot_format_32_Format_slot_format_32_0_0_get \(const xtensa_insnbuf insn,\s*"
        r"xtensa_insnbuf slotbuf\)\n\{\n(.*?)\n\}",
        src,
        re.S | re.M,
    )
    if not m:
        sys.exit("no format_32 slot getter")
    out = []
    for line in m.group(1).split("\n"):
        line = line.strip()
        a = re.fullmatch(r"slotbuf\[0\] = \(\(insn\[0\] & (0x[0-9a-f]+)\) >> (\d+)\);", line)
        b = re.fullmatch(
            r"slotbuf\[0\] = \(slotbuf\[0\] & ~(0x[0-9a-f]+)\) \| "
            r"\(\(\(insn\[0\] & (0x[0-9a-f]+)\) >> (\d+)\) << (\d+)\);",
            line,
        )
        c = re.fullmatch(
            r"slotbuf\[0\] = \(slotbuf\[0\] & ~(0x[0-9a-f]+)\) \| \(\(insn\[0\] & (0x[0-9a-f]+)\) << (\d+)\);",
            line,
        )
        if a:
            out.append(f"    let mut s = (insn & {a.group(1)}) >> {a.group(2)};")
        elif b:
            out.append(
                f"    s = (s & !{b.group(1)}) | (((insn & {b.group(2)}) >> {b.group(3)}) << {b.group(4)});"
            )
        elif c:
            out.append(f"    s = (s & !{c.group(1)}) | ((insn & {c.group(2)}) << {c.group(3)});")
        else:
            sys.exit(f"unexpected format_32 slot line: {line!r}")
    return out


TOKEN = re.compile(r"\s*(Field_\w+ \(insn\)|XTENSA_UNDEFINED|OPCODE_\w+|\w+|==|&&|\|\||[(){};])")


def tokenize(body):
    tokens = []
    pos = 0
    body = body.rstrip()
    while pos < len(body):
        m = TOKEN.match(body, pos)
        if not m:
            if body[pos:].strip() == "":
                break
            sys.exit(f"cannot tokenize near {body[pos:pos + 40]!r}")
        tokens.append(m.group(1))
        pos = m.end()
    return tokens


class Translator:
    def __init__(self, tokens, slot, used):
        self.t = tokens
        self.i = 0
        self.slot = slot
        self.used = used
        self.opcodes = set()

    def peek(self):
        return self.t[self.i] if self.i < len(self.t) else None

    def take(self, expected=None):
        tok = self.t[self.i]
        if expected is not None and tok != expected:
            sys.exit(f"expected {expected!r}, got {tok!r}")
        self.i += 1
        return tok

    def expr(self):
        # The tokens between the parentheses of an `if`.
        depth = 1
        out = []
        while True:
            tok = self.take()
            if tok == "(":
                depth += 1
            elif tok == ")":
                depth -= 1
                if depth == 0:
                    return " ".join(out).replace("( ", "(").replace(" )", ")")
            if tok.startswith("Field_"):
                m = re.fullmatch(r"Field_(\w+?)_Slot_(\w+)_get \(insn\)", tok)
                if m.group(2) != self.slot:
                    sys.exit(f"field of slot {m.group(2)} in decoder of {self.slot}")
                self.used.add((m.group(1), self.slot))
                tok = f"{SLOTS[self.slot]}_{m.group(1)}(s)"
            out.append(tok)

    def statement(self, indent):
        pad = "    " * indent
        tok = self.take()
        if tok == "if":
            self.take("(")
            cond = self.expr()
            lines = [f"{pad}if {cond} {{"]
            lines += self.block_or_statement(indent + 1)
            lines.append(f"{pad}}}")
            return lines
        if tok == "return":
            value = self.take()
            self.take(";")
            if value == "XTENSA_UNDEFINED":
                return [f"{pad}return None;"]
            self.opcodes.add(value[len('OPCODE_'):])
            return [f"{pad}return Some(Opcode::{value[len('OPCODE_'):]});"]
        sys.exit(f"unexpected token {tok!r}")

    def block_or_statement(self, indent):
        if self.peek() == "{":
            self.take("{")
            lines = []
            while self.peek() != "}":
                lines += self.statement(indent)
            self.take("}")
            return lines
        return self.statement(indent)


def parse_decoder(src, slot, used):
    m = re.search(
        rf"^Slot_{slot}_decode \(const xtensa_insnbuf insn\)\n\{{\n(.*?)\n\}}", src, re.S | re.M
    )
    if not m:
        sys.exit(f"no decoder for slot {slot}")
    tr = Translator(tokenize(m.group(1)), slot, used)
    lines = []
    while tr.peek() is not None:
        lines += tr.statement(1)
    if lines[-1] == "    return None;":
        lines[-1] = "    None"
    else:
        lines.append("    None")
    return lines, tr.opcodes


def field_fn(name, slot, steps):
    body = ["    let mut t = 0u32;"]
    for width, left, right in steps:
        shifted = f"((insn << {left}) >> {right})" if left else f"(insn >> {right})"
        if width >= 32:
            body.append(f"    t = {shifted};")
        else:
            body.append(f"    t = (t << {width}) | {shifted};")
    body.append("    t")
    return [
        "#[inline(always)]",
        f"fn {SLOTS[slot]}_{name}(insn: u32) -> u32 {{",
        *body,
        "}",
    ]


def generate(path):
    src = path.read_text()
    enum = parse_enum(src)
    mnemonics = parse_mnemonics(src)
    if len(enum) != len(mnemonics):
        sys.exit(f"{len(enum)} opcode ids but {len(mnemonics)} opcode table entries")
    for ident, mnem in zip(enum, mnemonics):
        if ident.upper() != mnem.upper().replace(".", "_"):
            sys.exit(f"opcode id {ident} does not match mnemonic {mnem}")
    fields = parse_fields(src)
    used = set()
    decoders = {}
    slot_opcodes = {}
    for slot in SLOTS:
        decoders[slot], slot_opcodes[slot] = parse_decoder(src, slot, used)
    f32_slot = parse_format32_slot(src)
    ar_list, getters = parse_ar_operands(src)
    ar_operands = dict(zip(enum, ar_list))
    ar_masks = {}
    for slot in SLOTS:
        arms = []
        for ident in enum:
            if ident not in slot_opcodes[slot] or not ar_operands[ident]:
                continue
            terms = []
            for field in ar_operands[ident]:
                kind, value = getters.get((field, slot), (None, None))
                if kind == "const":
                    terms.append(f"(1 << {value})")
                elif kind == "field":
                    used.add((value, slot))
                    terms.append(f"(1 << {SLOTS[slot]}_{value}(s))")
                else:
                    sys.exit(f"no getter for field {field} in slot {slot}")
            arms.append(f"        Opcode::{ident} => {' | '.join(terms)},")
        ar_masks[slot] = arms

    out = [
        "// AUTO-GENERATED. DO NOT EDIT BY HAND.",
        "// Generated by tools/xtensa/gen_opcodes.py from the libisa tables of the core",
        "// configuration (`xtensa-modules.inc.c`): Copyright (c) 2003-2021 Tensilica Inc.,",
        "// MIT license, see THIRD_PARTY_NOTICES.md.",
        "",
        "#![allow(clippy::all, unused_parens)]",
        "",
        f"/// The {len(enum)} opcodes of the core.",
        "#[allow(non_camel_case_types)]",
        "#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]",
        "#[repr(u16)]",
        "pub enum Opcode {",
    ]
    out += [f"    {ident}," for ident in enum]
    out += ["}", "", f"pub const OPCODE_COUNT: usize = {len(enum)};", ""]
    out += ["/// Mnemonics, indexed by `Opcode as usize`.", "pub static MNEMONICS: [&str; OPCODE_COUNT] = ["]
    out += [f'    "{m}",' for m in mnemonics]
    out += ["];", ""]
    out += ["/// Every opcode, indexed by `Opcode as usize`.", "pub static OPCODES: [Opcode; OPCODE_COUNT] = ["]
    out += [f"    Opcode::{ident}," for ident in enum]
    out += ["];", ""]
    out += [
        "impl Opcode {",
        "    pub fn mnemonic(self) -> &'static str {",
        "        MNEMONICS[self as usize]",
        "    }",
        "",
        "    pub fn from_index(i: usize) -> Option<Opcode> {",
        "        OPCODES.get(i).copied()",
        "    }",
        "}",
        "",
        "/// The single slot of a format_32 instruction, from the 32-bit instruction word.",
        "#[inline]",
        "pub fn slot_format_32(insn: u32) -> u32 {",
        *f32_slot,
        "    s",
        "}",
        "",
    ]
    for (name, slot) in sorted(used):
        out += field_fn(name, slot, fields[(name, slot)])
        out.append("")
    for slot, short in SLOTS.items():
        out.append(f"/// Decodes the slot of a {short} instruction.")
        out.append(f"pub fn decode_{short}(s: u32) -> Option<Opcode> {{")
        out += decoders[slot]
        out.append("}")
        out.append("")
        out.append(f"/// The AR registers (window-relative numbers, as a bit mask) that the operands of")
        out.append(f"/// a {short} instruction name.")
        out.append(f"pub fn ar_mask_{short}(op: Opcode, s: u32) -> u32 {{")
        if ar_masks[slot]:
            out.append("    match op {")
            out += ar_masks[slot]
            out.append("        _ => 0,")
            out.append("    }")
        else:
            out.append("    let _ = (op, s);")
            out.append("    0")
        out.append("}")
        out.append("")
    return "\n".join(out).rstrip() + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("modules", type=pathlib.Path, help="xtensa-modules.inc.c of the core")
    ap.add_argument(
        "-o",
        "--output",
        type=pathlib.Path,
        default=pathlib.Path(__file__).resolve().parents[2] / "src/isa/xtensa/generated/opcodes.rs",
    )
    args = ap.parse_args()
    args.output.write_text(generate(args.modules))
    print(f"wrote {args.output}")


if __name__ == "__main__":
    main()
