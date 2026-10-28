//! Compare the native adapter with the independent Win32 mapped-name entry.
use super::*;
use crate::user::windows::mapped_filename::Filename;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

#[link(name = "kernel32")]
unsafe extern "system" {
    fn K32GetMappedFileNameW(process: Handle, address: Handle, output: *mut u16, size: u32) -> u32;
}

fn control(view: &View) -> Vec<u16> {
    let mut output = vec![0u16; 32768];
    // SAFETY: current process, test-owned live host view and exclusive bounded
    // initialized UTF-16 output. No guest state participates in this oracle.
    let length = unsafe {
        K32GetMappedFileNameW(
            (-1isize) as Handle,
            view.0,
            output.as_mut_ptr(),
            output.len() as u32,
        )
    };
    assert!(
        length != 0 && length < output.len() as u32,
        "{}",
        io::Error::last_os_error()
    );
    output.truncate(length as usize);
    output
}

pub(crate) fn independent_name(file: &File) -> Vec<u16> {
    control(&View::image(file).unwrap())
}

struct Fixture(PathBuf);
impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).expect("remove owned mapped-filename fixture");
    }
}

#[test]
fn mapped_filename_native_retains_file_identity_across_close_rename_and_replacement() {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let fixture = Fixture(std::env::temp_dir().join(format!(
        "rax-mapped-filename-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    )));
    std::fs::create_dir(&fixture.0).unwrap();
    let arch = if cfg!(target_arch = "aarch64") {
        "arm64"
    } else if cfg!(target_arch = "x86") {
        "x86"
    } else {
        "x64"
    };
    let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/user/windows/native_cli/bin")
        .join(arch)
        .join("probe.exe");
    let original = fixture.0.join("original mapped λ.exe");
    let renamed = fixture.0.join("renamed mapped λ.exe");
    std::fs::copy(&source, &original).unwrap();
    let file = File::open(&original).unwrap();
    let name = Filename::image(&file).unwrap().unwrap();
    let native = View::image(&file).unwrap();
    drop(file);
    let before = name.read().unwrap();
    assert_eq!(before, control(&native));
    assert!(before.ends_with(&"\\original mapped λ.exe".encode_utf16().collect::<Vec<_>>()));
    std::fs::rename(&original, &renamed).unwrap();
    let after = name.read().unwrap();
    assert_eq!(after, control(&native));
    assert!(after.ends_with(&"\\renamed mapped λ.exe".encode_utf16().collect::<Vec<_>>()));
    assert_ne!(after, before);
    std::fs::copy(&source, &original).unwrap();
    assert_eq!(
        name.read().unwrap(),
        after,
        "replacement pathname must not change the mapped object"
    );
    drop(native);
    drop(name);
}
