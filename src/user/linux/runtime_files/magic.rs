//! Read-only package data needed by the installed libmagic.
use crate::user::{mm::HostFileSource, supplied_fs::Files};
use std::{
    collections::BTreeMap,
    ffi::CString,
    fs::File,
    io,
    os::fd::{AsRawFd, FromRawFd},
    path::Path,
};

const DATABASE: &str = "/usr/lib/file/magic.mgc";
const SHARE_PATHS: [&str; 2] = ["/usr/share/misc/magic.mgc", "/usr/share/file/magic.mgc"];

pub(super) fn select(files: Files, root: &Path, executable: Option<&str>) -> io::Result<Files> {
    let overlaps = |path: &str| {
        executable.is_some_and(|image| {
            image == path
                || image
                    .strip_prefix(path)
                    .is_some_and(|rest| rest.starts_with('/'))
                || path
                    .strip_prefix(image)
                    .is_some_and(|rest| rest.starts_with('/'))
        })
    };
    let mut backings = BTreeMap::new();
    for path in [DATABASE].into_iter().chain(SHARE_PATHS) {
        if !overlaps(path)
            && files
                .default_runtime_entry_available(path, None)
                .map_err(io::Error::other)?
            && let Ok(source) = open_database(root, path)
        {
            backings.insert(path.to_owned(), source.into());
        }
    }
    let mut files = files
        .with_selected_backings(backings)
        .map_err(io::Error::other)?;

    // Debian installs these aliases using the relative spelling. Recreate
    // vetted links in the guest so a caller's database at the target wins.
    for alias in SHARE_PATHS.into_iter().filter(|alias| !overlaps(alias)) {
        let host = root.join(alias.trim_start_matches('/'));
        let parent = host.parent().expect("package database has a parent");
        if parent.canonicalize().ok().as_deref() == Some(parent)
            && host.read_link().is_ok_and(|link| {
                link == Path::new("../../lib/file/magic.mgc") || link == Path::new(DATABASE)
            })
        {
            files = files
                .with_native_symlink(alias, DATABASE)
                .map_err(io::Error::other)?;
        }
    }
    Ok(files)
}

fn open_database(root: &Path, path: &str) -> io::Result<HostFileSource> {
    let mut directory = File::open(root)?;
    let (parent, name) = path.rsplit_once('/').expect("absolute package path");
    for component in parent[1..].split('/') {
        directory = open_child(&directory, component, libc::O_DIRECTORY)?;
    }
    let file = open_child(&directory, name, libc::O_NONBLOCK)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "compiled libmagic database",
        ));
    }
    HostFileSource::new(file)
}

fn open_child(directory: &File, name: &str, flags: libc::c_int) -> io::Result<File> {
    let name = CString::new(name)?;
    // SAFETY: the directory handle and NUL-terminated component are live.
    // O_NOFOLLOW applies to each single-component lookup.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | flags,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a successful openat returns a new owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::user::supplied_fs::{Error, test_backing::TestFile};
    use std::{fs, os::unix::fs::symlink};

    const MISC: &str = SHARE_PATHS[0];
    const SHARE: &str = SHARE_PATHS[1];

    #[test]
    fn compiled_database_aliases_follow_guest_overrides() {
        let fixture = TestFile::new(b"unused", 6);
        let root = &fixture.dir;
        for path in ["usr/lib/file", "usr/share/misc", "usr/share/file", "etc"] {
            fs::create_dir_all(root.join(path)).unwrap();
        }
        fs::write(root.join("usr/lib/file/magic.mgc"), b"packaged").unwrap();
        fs::write(root.join("etc/magic"), b"local rules").unwrap();
        fs::write(root.join("usr/share/misc/private"), b"unselected").unwrap();
        symlink(
            "../../lib/file/magic.mgc",
            root.join("usr/share/misc/magic.mgc"),
        )
        .unwrap();
        symlink(DATABASE, root.join("usr/share/file/magic.mgc")).unwrap();

        let files = super::super::select_installed(&Files::default(), root).unwrap();
        for path in [DATABASE, MISC, SHARE] {
            assert_eq!(&*files.read(path).unwrap(), b"packaged", "{path}");
        }
        assert_eq!(
            files
                .lookup_with_follow(MISC, false)
                .unwrap()
                .1
                .link_target(),
            Some(DATABASE.as_bytes())
        );
        for path in ["/etc/magic", "/usr/share/misc/private"] {
            assert!(matches!(files.lookup(path), Err(Error::NotFound)), "{path}");
        }

        let supplied = Files::new(BTreeMap::from([
            (DATABASE.into(), b"caller database"[..].into()),
            (SHARE.into(), b"caller alias"[..].into()),
        ]))
        .unwrap();
        let files = super::super::select_installed(&supplied, root).unwrap();
        assert_eq!(&*files.read(MISC).unwrap(), b"caller database");
        assert_eq!(&*files.read(SHARE).unwrap(), b"caller alias");

        let mounted = TestFile::new(b"unused", 6);
        let supplied = Files::default()
            .with_host_roots(BTreeMap::from([(
                "/usr/share/misc".into(),
                mounted.dir.clone(),
            )]))
            .unwrap();
        let files = super::super::select_installed(&supplied, root).unwrap();
        assert!(matches!(files.lookup(MISC), Err(Error::NotFound)));
        assert_eq!(&*files.read(SHARE).unwrap(), b"packaged");

        for executable in ["/usr/share/misc", MISC, "/usr/share/misc/magic.mgc/tool"] {
            let files = super::super::select_installed_for_executable(
                &Files::default(),
                root,
                Some(executable),
            )
            .unwrap();
            assert!(matches!(files.lookup(MISC), Err(Error::NotFound)));
        }
    }

    #[test]
    fn compiled_database_rejects_links_outside_package_paths() {
        let fixture = TestFile::new(b"unused", 6);
        let external = TestFile::new(b"outside", 7);
        let root = &fixture.dir;
        fs::create_dir_all(root.join("usr/lib")).unwrap();
        fs::create_dir_all(root.join("usr/share/misc")).unwrap();
        fs::create_dir_all(root.join("etc")).unwrap();
        fs::write(root.join("etc/private"), b"unselected").unwrap();
        fs::write(external.dir.join("magic.mgc"), b"outside").unwrap();
        symlink(&external.dir, root.join("usr/lib/file")).unwrap();
        symlink(&external.path, root.join("usr/share/misc/magic.mgc")).unwrap();
        symlink("../../etc/private", root.join("usr/share/misc/local")).unwrap();
        fs::create_dir(root.join("usr/share/file")).unwrap();
        fs::write(root.join("usr/share/file/magic.mgc"), b"standalone package").unwrap();

        let files = super::super::select_installed(&Files::default(), root).unwrap();
        for path in [DATABASE, MISC, "/usr/share/misc/local", "/etc/private"] {
            assert!(matches!(files.lookup(path), Err(Error::NotFound)), "{path}");
        }
        assert_eq!(&*files.read(SHARE).unwrap(), b"standalone package");
    }
}
