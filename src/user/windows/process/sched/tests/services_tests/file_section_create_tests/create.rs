//! File-backed construction reaches a real immutable image section.
use super::*;
use crate::user::image::pe::PeImage;
use crate::user::windows::fs::{FileIdentity, FileLifetime};
use crate::user::windows::objects::FileObj;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(windows)]
#[path = "installed.rs"]
mod installed;
#[path = "mapped_identity.rs"]
mod mapped_identity;
#[path = "ownership.rs"]
mod ownership;
#[path = "replay.rs"]
mod replay;

fn insert_file(p: &mut Proc, path: &std::path::Path, access: u32) -> u64 {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.access_mode(0x1000A1).share_mode(7);
    }
    let host = options.open(path).unwrap();
    let metadata = host.metadata().unwrap();
    let identity = FileIdentity::of_open(path, Some(&host), &metadata).unwrap();
    let id = p.objects.create(Object::File(FileObj {
        host: Some(host),
        host_path: path.to_owned(),
        path: "\\??\\C:\\private-image.dll".into(),
        access: 0x1000A1,
        share: 7,
        lifetime: Arc::new(FileLifetime::new(identity)),
        null: false,
        append: false,
        delete_on_close: false,
        directory: false,
        overlapped: false,
    }));
    p.objects.open_access(id, false, access).unwrap().into()
}

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        loop {
            let path = std::env::temp_dir().join(format!(
                "rax-file-section-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match std::fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("private section fixture: {error}"),
            }
        }
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).expect("remove private section fixtures");
    }
}

fn image(arch: WinArch) -> &'static [u8] {
    match arch {
        WinArch::X86 => {
            include_bytes!("../../../../../../../../tests/fixtures/user/windows/bin/x86/smoke.exe")
        }
        WinArch::X64 => {
            include_bytes!("../../../../../../../../tests/fixtures/user/windows/bin/x64/smoke.exe")
        }
        WinArch::Arm64 => include_bytes!(
            "../../../../../../../../tests/fixtures/user/windows/bin/arm64/smoke.exe"
        ),
    }
}

#[test]
fn native_section_file_image_create_publishes_a_typed_owned_section_all_abis() {
    for arch in WinArch::ALL {
        let directory = Directory::new();
        let path = directory.0.join("fixture.dll");
        let data = image(arch);
        let parsed = PeImage::parse(data).unwrap();
        std::fs::write(&path, data).unwrap();
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            options.access_mode(0x100021).share_mode(7);
        }
        let host = options.open(&path).unwrap();
        let metadata = host.metadata().unwrap();
        let identity = FileIdentity::of_open(&path, Some(&host), &metadata).unwrap();
        let (mut process, mut thread) = fixture(arch, "NtCreateSection", SERVICE);
        let p = process.state_mut();
        let file = u64::from(p.objects.insert(Object::File(FileObj {
            host: Some(host),
            host_path: path,
            path: "\\??\\C:\\fixture.dll".into(),
            access: 0x100021,
            share: 7,
            lifetime: Arc::new(FileLifetime::new(identity)),
            null: false,
            append: false,
            delete_on_close: false,
            directory: false,
            overlapped: false,
        })));
        let output = scratch(p);
        p.space.wr(output, &[0xa5; 16]).unwrap();
        assert_eq!(
            call(p, &mut thread, &[output, 0xD, 0, 0, 0x10, 0x01000000, file]),
            STATUS_SUCCESS,
            "{arch}"
        );
        let handle = get(p, output);
        assert_eq!(p.objects.access(handle), Some(0xD));
        let Object::ImageSection(section) = p.objects.get(handle).unwrap() else {
            panic!("file-backed image must publish a typed Section");
        };
        assert_eq!(section.attributes, 0x01800000);
        assert_eq!(section.size, u64::from(parsed.headers().size_of_image));
        assert!(
            section.path.is_empty(),
            "unnamed section has no object-manager name"
        );
        let retained = section.clone();
        p.objects.close(file).unwrap();
        let template = retained.image_for(arch).unwrap();
        assert_eq!(template.bytes.get(..2), Some(b"MZ".as_slice()));
        assert_eq!(template.machine, parsed.headers().machine);
        assert_eq!(template.bytes.len() as u64, retained.size);
        let duplicate = p.objects.duplicate(handle, false).unwrap();
        p.objects.close(handle).unwrap();
        assert!(matches!(
            p.objects.get(duplicate.into()),
            Some(Object::ImageSection(_))
        ));
        p.objects.close(duplicate.into()).unwrap();
    }
}
