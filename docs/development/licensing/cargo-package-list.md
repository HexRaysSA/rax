# Cargo package-list path separators

`tools/licensing/check.py` validates the entries printed by
`cargo package --list`. Cargo prints each entry's host-relative path string, so
Windows prints `src\lib.rs` for the archive member `src/lib.rs`. The checker
converts the host separator to `/` before applying its archive-path rules.

## Source record

| Field | Value |
|---|---|
| Title | `src/ops/cargo_package/mod.rs` |
| Organization | The Rust Project Developers (`rust-lang/cargo`) |
| Revision | master `694054f34bcb04025b16d0eaf075038c0e58a15d`; last change to this file `78f8bc7f42dbbbce93a28e3f7f77907d4ba95b80` (2026-08-27) |
| Source URL | <https://github.com/rust-lang/cargo/blob/694054f34bcb04025b16d0eaf075038c0e58a15d/src/ops/cargo_package/mod.rs> |
| Retrieved | 2026-09-23 |
| SHA-256 of retrieved file | `8bce4f42f8b5344e1af7fd7b491e837431e239c721fd5ededcdec125bb3cc833` |
| License | MIT OR Apache-2.0 |

Excerpts, verbatim. `--list` prints `ArchiveFile::rel_str` (lines 306-313):

```rust
        if opts.list {
            match opts.fmt {
                PackageMessageFormat::Human => {
                    // While this form is called "human",
                    // it keeps the old file-per-line format for compatibility.
                    for ar_file in &ar_files {
                        drop_println!(ws.gctx(), "{}", ar_file.rel_str);
                    }
```

`rel_str` is the host path string, without separator conversion
(lines 508-512):

```rust
        let rel_path = src_file.strip_prefix(&root)?;
        check_filename(rel_path, &mut ws.gctx().shell())?;
        let rel_str = rel_path.to_str().ok_or_else(|| {
            anyhow::format_err!("non-utf8 path in source directory: {}", rel_path.display())
        })?;
```

## Observed failure

Licensing run 35882714680 (commit `f209253dc`) passed on `ubuntu-24.04` and
`macos-15` with 2,349 `rax` package files. It failed on `windows-2022` with
`rax: unexpected package files`. The same listing with `/` replaced by `\`
produced a 138,945-character error message from the previous checker. The
GitHub job log did not show that line.
