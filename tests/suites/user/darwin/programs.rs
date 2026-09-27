//! System programs behave under `rax-user` as they do natively.

use std::path::Path;

use super::support::{build_dir, comparable, compare};

fn program(path: &str, arch: &str, args: &[&str], cwd: Option<&Path>) {
    let what = format!("{path} {}", args.join(" "));
    if !comparable(&what, arch) {
        return;
    }
    compare(&what, Path::new(path), arch, args, &[], cwd);
}

#[test]
fn echo() {
    for arch in ["arm64", "x86_64"] {
        program("/bin/echo", arch, &["hello,", "world"], None);
        program("/bin/echo", arch, &["-n", "no newline"], None);
    }
}

#[test]
fn true_and_false() {
    for arch in ["arm64", "x86_64"] {
        program("/usr/bin/true", arch, &[], None);
        program("/usr/bin/false", arch, &[], None);
    }
}

#[test]
fn cat_a_file() {
    let dir = build_dir().join("cat");
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("text");
    std::fs::write(&file, b"line one\nline two\n\x00binary\xff\n").unwrap();
    for arch in ["arm64", "x86_64"] {
        program("/bin/cat", arch, &[file.to_str().unwrap()], None);
        program("/bin/cat", arch, &["-n", file.to_str().unwrap()], None);
        program("/bin/cat", arch, &["missing-file"], Some(&dir));
    }
}

#[test]
fn env_runs_a_program() {
    for arch in ["arm64", "x86_64"] {
        program("/usr/bin/env", arch, &["/bin/echo", "via", "env"], None);
        program(
            "/usr/bin/env",
            arch,
            &["-i", "A=1", "/usr/bin/printenv"],
            None,
        );
        program("/usr/bin/env", arch, &["/nonexistent/program"], None);
    }
}

#[test]
fn sh_runs_commands() {
    let script = "echo one; /bin/echo two; x=$(/bin/echo three); echo \"$x\"; \
                  /usr/bin/false || echo \"false=$?\"; exit 3";
    for arch in ["arm64", "x86_64"] {
        program("/bin/sh", arch, &["-c", script], None);
    }
}
