//! Run host-fork and peer-EOF tests outside the parallel libtest process.
//! Process creation can retain unrelated tests' socket peers before the child
//! closes or execs them. Create EOF-sensitive sockets only in selected children.

/// Return true after running `test` in an isolated process. The selected child
/// returns false so the caller executes its original test body exactly once.
pub(crate) fn isolated(test: &str) -> bool {
    const CHILD: &str = "RAX_ISOLATED_HOST_FORK_TEST";
    if std::env::var_os(CHILD).as_deref() == Some(std::ffi::OsStr::new(test)) {
        return false;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", test, "--nocapture", "--test-threads=1"])
        .env(CHILD, test)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success()
            && stdout.lines().any(|line| {
                line.starts_with("test result: ok. 1 passed; 0 failed; 0 ignored;")
            }),
        "isolated host-fork test {test} failed: {stdout}{}",
        String::from_utf8_lossy(&output.stderr)
    );
    true
}
