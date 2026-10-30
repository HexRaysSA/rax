//! Independent installed-GDB interoperability, explicitly selected by CI.
use super::*;
#[test]
#[ignore = "Requires RAX_GDB pointing to an installed GDB; explicitly run in the debugger CI lane"]
fn installed_gdb_enumerates_selects_steps_and_writes_an_ap() {
    let vm = Running::listen(4);
    let script = "import gdb\nassert len(gdb.selected_inferior().threads()) == 4\ngdb.execute('set scheduler-locking step')\ngdb.execute('thread 2')\nassert int(gdb.parse_and_eval('$rax')) == 0x101\ngdb.execute('stepi')\nassert int(gdb.parse_and_eval('$rax')) == 0x102\ngdb.execute('set $rax=0x1234')\nassert int(gdb.parse_and_eval('$rax')) == 0x1234\nassert int(gdb.parse_and_eval('$fctrl')) == 0x37f\ngdb.execute('set $fctrl=0x27f')\nassert int(gdb.parse_and_eval('$fctrl')) == 0x27f\ngdb.execute('thread 1')\nassert int(gdb.parse_and_eval('$rax')) == 0x100\nassert int(gdb.parse_and_eval('$fctrl')) == 0x37f\nprint('RAX_GDB_SMP_OK')";
    run_script(vm, script, "RAX_GDB_SMP_OK");
}
pub(super) fn run_script(vm: Running, script: &str, marker: &str) {
    use std::process::{Command, Stdio};
    let executable = std::env::var_os("RAX_GDB").expect("set RAX_GDB to the GDB executable");
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory =
        std::env::temp_dir().join(format!("rax-gdb-client-{}-{nonce}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    let python = format!("python exec({script:?})");
    let mut child = Command::new(executable)
        .args([
            "--batch",
            "-nx",
            "-ex",
            "set architecture i386:x86-64",
            "-ex",
            "set remotetimeout 10",
            "-ex",
            &format!("target remote {}", vm.address),
            "-ex",
            &python,
            "-ex",
            "detach",
        ])
        .stdin(Stdio::null())
        .stdout(std::fs::File::create(directory.join("stdout")).unwrap())
        .stderr(std::fs::File::create(directory.join("stderr")).unwrap())
        .spawn()
        .unwrap();
    let start = std::time::Instant::now();
    let mut timed_out = false;
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if start.elapsed() > std::time::Duration::from_secs(45) {
            timed_out = true;
            child.kill().unwrap();
            break child.wait().unwrap();
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    };
    let out = std::fs::read_to_string(directory.join("stdout")).unwrap();
    let err = std::fs::read_to_string(directory.join("stderr")).unwrap();
    std::fs::remove_dir_all(directory).unwrap();
    println!("GDB stdout:\n{out}\nGDB stderr:\n{err}");
    assert!(
        !timed_out
            && status.success()
            && out.contains(marker)
            && !err.contains("target description")
            && !err.contains("target-supplied description")
            && !err.contains("AssertionError")
            && !err.contains("Traceback")
            && !err.contains("Error occurred")
            && !err.contains("Python Exception"),
        "{status}"
    );
}
