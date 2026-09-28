//! Unmodified compiler-selected main/wmain startup through normal DLL detach.

fn run(arch: &str, program: &str, slice: u64) {
    assert!(matches!(arch, "x86" | "x64" | "arm64"));
    assert!(matches!(program, "main" | "wmain"));
    assert!(matches!(slice, 1 | 4096));
    let source = super::fixtures().join(format!("crt_stdio/bin/{arch}/ordinary/{program}.exe"));
    let original = std::fs::read(source).unwrap();
    let temp = super::TemporaryImage::new(&format!("ordinary-{arch}-{program}-{slice}"), &original);
    let drive = format!("C={}", temp.directory.display());
    let image = temp.path.to_str().unwrap();
    let slice = slice.to_string();
    let output = super::cli_support::run(
        &[
            "--os",
            "windows",
            "--memory",
            "64M",
            "--drive",
            &drive,
            "--cwd",
            "C:\\",
            "--slice",
            &slice,
            "--seed",
            "1",
            "--clear-env",
            image,
        ],
        &[("RAX_NO_JIT", "1")],
        None,
        std::time::Duration::from_secs(30),
    );
    assert_eq!(
        output.status,
        Some(0),
        "{arch}/{program} slice={slice}: stderr={:?}, stdout={:?}, signal={:?}",
        output.stderr,
        output.stdout,
        output.signal
    );
    assert!(output.stdout.is_empty() && output.stderr.is_empty());
    assert_eq!(std::fs::read(&temp.path).unwrap(), original);
}

macro_rules! case {
    ($name:ident, $arch:literal, $program:literal, $slice:literal) => {
        #[test]
        fn $name() {
            run($arch, $program, $slice);
        }
    };
}

case!(x86_main_slice_1, "x86", "main", 1);
case!(x86_wmain_slice_1, "x86", "wmain", 1);
case!(x64_main_slice_1, "x64", "main", 1);
case!(x64_wmain_slice_1, "x64", "wmain", 1);
case!(arm64_main_slice_1, "arm64", "main", 1);
case!(arm64_wmain_slice_1, "arm64", "wmain", 1);
case!(x86_main_slice_4096, "x86", "main", 4096);
case!(x86_wmain_slice_4096, "x86", "wmain", 4096);
case!(x64_main_slice_4096, "x64", "main", 4096);
case!(x64_wmain_slice_4096, "x64", "wmain", 4096);
case!(arm64_main_slice_4096, "arm64", "main", 4096);
case!(arm64_wmain_slice_4096, "arm64", "wmain", 4096);
