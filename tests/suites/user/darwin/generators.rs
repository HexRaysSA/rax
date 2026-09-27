//! The generated Darwin tables are what their generators produce from the
//! vendored sources: `tools/darwin/gen_abi.py --check` and
//! `tools/darwin/gen_mig.py --check` regenerate in memory and compare.

use std::path::PathBuf;
use std::process::Command;

fn check(script: &str, needs_mig: bool) {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    if Command::new("python3").arg("--version").output().is_err() {
        eprintln!("skipped {script}: python3 is unavailable");
        return;
    }
    if needs_mig
        && Command::new("xcrun")
            .args(["-f", "mig"])
            .output()
            .map_or(true, |o| !o.status.success())
    {
        eprintln!("skipped {script}: mig is unavailable");
        return;
    }
    let out = Command::new("python3")
        .arg(root.join("tools/darwin").join(script))
        .arg("--check")
        .output()
        .expect("run generator");
    assert!(
        out.status.success(),
        "{script} --check: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn abi_tables_are_current() {
    check("gen_abi.py", false);
}

#[test]
fn mig_ids_are_current() {
    check("gen_mig.py", true);
}
