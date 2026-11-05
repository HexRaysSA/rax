# Portable SMIR framing tools

These tools implement the experimental 0.1 envelope described in
[the specification](../../docs/specifications/smir/portable/README.md).
They do not compile, link, verify semantics or execute portable programs.

Run from the repository root:

```sh
python3 tools/smir-format/check_spec.py
python3 -m unittest discover -s tools/smir-format -p 'test_*.py' -v
python3 tools/smir-format/codec.py encode module.json --output module.smo
python3 tools/smir-format/codec.py inspect module.smo
```

Encoder JSON contains `kind` (1 object, 2 image), optional `entry` (default
4294967295, no entry), and `sections`, each containing integer `kind`, boolean
`required` and payload `hex`. The golden fixtures additionally wrap this input
as `module` and include independently audited `encoded_hex`.

The cross-codec tests require Rust 2024 and fail if the compiler/probe cannot
run; they do not silently skip a missing dependency. Files and executables are
temporary. Randomized mutations use seed `0x534d4952`.

For a macOS installation whose default Clang lacks a usable SDK/header setup,
select the configured Apple compiler explicitly:

```sh
CXX=/usr/bin/clang++ python3 -m unittest discover -s tools/smir-format -p 'test_*.py' -v
```

The C++ probe requires a C++20 compiler. Missing compiler/SDK support is a test
failure, not a skipped comparison.
