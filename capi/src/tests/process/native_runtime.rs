//! Installed runtime grants exercised through the exported C process interface.
use super::*;

#[cfg(all(windows, target_pointer_width = "64"))]
#[path = "native_runtime/token_duplicate.rs"]
mod token_duplicate;

fn refused(image: &[u8], options: &str, supplied: &[RaxProcessImage], status: RaxStatus) -> String {
    let mut handle = ptr::null_mut();
    assert_eq!(
        rax_process_open_image(
            image.as_ptr(),
            image.len(),
            options.as_ptr().cast(),
            options.len(),
            supplied.as_ptr(),
            supplied.len(),
            &mut handle,
        ),
        status,
        "{}",
        error(),
    );
    assert!(handle.is_null(), "refused open published a process");
    error()
}

#[test]
fn native_option_is_strict_and_host_mismatch_never_falls_back() {
    let image = fixtures()[0].1;
    for value in ["null", "0", "1", "\"true\"", "[]", "{}"] {
        let message = refused(
            image,
            &format!("{{\"native_runtime\":{value}}}"),
            &[],
            RaxStatus::Arg,
        );
        assert_eq!(message, "native_runtime must be a boolean");
    }
    for (personality, matching_host) in [
        ("windows", cfg!(windows)),
        ("linux", cfg!(target_os = "linux")),
        ("darwin", cfg!(target_os = "macos")),
    ] {
        if !matching_host {
            let message = refused(
                image,
                &format!("{{\"personality\":\"{personality}\",\"native_runtime\":true}}"),
                &[],
                RaxStatus::Unsupported,
            );
            assert!(message.contains("host"), "{message}");
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn installed_dynamic_programs_run_without_supplied_dependencies_or_general_host_access() {
    let personality = if cfg!(target_os = "linux") {
        "linux"
    } else {
        "darwin"
    };
    for (path, arguments, expected) in [
        (
            if cfg!(target_os = "linux") {
                "/bin/true"
            } else {
                "/usr/bin/true"
            },
            serde_json::json!([]),
            "",
        ),
        (
            "/usr/bin/printf",
            serde_json::json!(["%s\\n", "native-c-api"]),
            "native-c-api\n",
        ),
    ] {
        let image = std::fs::read(path).expect("installed system program");
        let options = serde_json::json!({
            "personality":personality, "native_runtime":true, "arguments":arguments,
            "memory_bytes":268435456, "slice_instructions":4096,
        })
        .to_string();
        let process = open(&image, &options);
        let before = info(&process);
        assert_eq!(before["capabilities"]["native_runtime"], true);
        assert_eq!(before["capabilities"]["host_filesystem"], false);
        assert_eq!(before["capabilities"]["host_services"], false);
        #[cfg(target_os = "macos")]
        assert_eq!(
            before["architecture"],
            if cfg!(target_arch = "aarch64") {
                "aarch64"
            } else {
                "x86_64"
            }
        );
        let result = run_installed_posix(&process, path);
        assert_eq!(result.exit_code, 0);
        let mut output = vec![0; 65536];
        let mut size = 0;
        assert_eq!(
            rax_process_output_read(
                process.0,
                RAX_PROCESS_STDOUT,
                output.as_mut_ptr(),
                output.len(),
                &mut size
            ),
            RaxStatus::Ok
        );
        assert_eq!(&output[..size], expected.as_bytes());

        // A supplied malformed interpreter/dyld must be used ahead of installed
        // bytes; otherwise this same executable would open successfully again.
        #[cfg(target_os = "macos")]
        let dependency = "/usr/lib/dyld".to_owned();
        #[cfg(target_os = "linux")]
        let dependency = String::from_utf8(
            rax_engine::user::image::elf::ElfImage::parse_self_described(&image)
                .unwrap()
                .interpreter()
                .expect("dynamic ELF interpreter")
                .to_vec(),
        )
        .unwrap();
        let broken = b"invalid supplied interpreter";
        let supplied = RaxProcessImage {
            path: dependency.as_ptr().cast(),
            path_size: dependency.len(),
            data: broken.as_ptr(),
            data_size: broken.len(),
        };
        let message = refused(&image, &options, &[supplied], RaxStatus::Format);
        assert!(!message.is_empty());
    }
}

#[cfg(target_os = "macos")]
#[test]
fn installed_uname_matches_native_kernel_version_through_closed_c_abi() {
    let path = "/usr/bin/uname";
    let native = std::process::Command::new(path)
        .args(["-rsv"])
        .env_clear()
        .output()
        .unwrap();
    assert!(native.status.success());
    assert!(native.stderr.is_empty());
    let options = serde_json::json!({
        "personality": "darwin",
        "guest_path": path,
        "arguments": ["-rsv"],
        "native_runtime": true,
        "memory_bytes": 268435456,
    });
    let process = open(&std::fs::read(path).unwrap(), &options.to_string());
    let state = info(&process);
    assert_eq!(state["capabilities"]["native_runtime"], true);
    assert_eq!(state["capabilities"]["host_filesystem"], false);
    assert_eq!(state["capabilities"]["host_services"], false);
    assert_eq!(run_installed_posix(&process, path).exit_code, 0);
    assert_eq!(
        capture_installed_posix_stream(&process, RAX_PROCESS_STDOUT),
        native.stdout
    );
    assert_eq!(
        capture_installed_posix_stream(&process, RAX_PROCESS_STDERR),
        native.stderr
    );
}

#[cfg(target_os = "macos")]
#[test]
fn installed_darwin_sysctl_reads_closed_kernel_nodes() {
    let environment = [("LC_ALL", "C")];
    let release = std::process::Command::new("/usr/bin/uname")
        .arg("-r")
        .env_clear()
        .output()
        .unwrap();
    assert!(release.status.success());
    assert!(release.stderr.is_empty());
    let mut expected = b"Darwin\n".to_vec();
    expected.extend_from_slice(&release.stdout);
    expected.extend_from_slice(b"16\n");
    compare_installed_posix_output(
        "darwin",
        "/usr/sbin/sysctl",
        &["-n", "kern.ostype", "kern.osrelease", "kern.ngroups"],
        &environment,
        &expected,
    );
}

#[cfg(target_os = "macos")]
#[test]
fn installed_darwin_stat_and_du_report_file_metadata_through_closed_c_abi() {
    use std::os::unix::fs::MetadataExt;

    let path = "/usr/bin/true";
    let metadata = std::fs::metadata(path).unwrap();
    let environment = [("LC_ALL", "C")];
    let stat = format!(
        "{:o} {} {} {} {} {}\n",
        metadata.mode(),
        metadata.size(),
        metadata.uid(),
        metadata.gid(),
        metadata.blocks(),
        metadata.mtime(),
    );
    compare_installed_posix_output(
        "darwin",
        "/usr/bin/stat",
        &["-f", "%p %z %u %g %b %m", path],
        &environment,
        stat.as_bytes(),
    );
    let du = format!("{}\t{path}\n", metadata.blocks().div_ceil(2));
    compare_installed_posix_output(
        "darwin",
        "/usr/bin/du",
        &["-k", path],
        &environment,
        du.as_bytes(),
    );
}

#[cfg(target_os = "macos")]
#[test]
fn installed_darwin_find_enumerates_programs_and_executes_children() {
    let find = "/usr/bin/find";
    let environment = [("LC_ALL", "C"), ("PATH", "/usr/bin:/bin")];
    for (suffix, stdout) in [
        (&[][..], b"/usr/bin/true\n".as_slice()),
        (
            &["-exec", "/usr/bin/printf", "child:%s\\n", "{}", ";"][..],
            b"child:/usr/bin/true\n".as_slice(),
        ),
        (
            &["-exec", "/usr/bin/printf", "child:%s\\n", "{}", "+"][..],
            b"child:/usr/bin/true\n".as_slice(),
        ),
        (&["-execdir", "/bin/pwd", ";"][..], b"/usr/bin\n".as_slice()),
    ] {
        let mut arguments = vec!["/usr/bin", "-maxdepth", "1", "-name", "true"];
        arguments.extend_from_slice(suffix);
        compare_installed_posix_output("darwin", find, &arguments, &environment, stdout);
    }
}

#[cfg(target_os = "macos")]
#[test]
fn installed_darwin_shell_executes_system_directory_programs() {
    for (command, expected) in [
        (
            "exec /sbin/md5 -q -s rax",
            b"0b1c108d8b9c46d402a502c5b6b9261c\n".as_slice(),
        ),
        (
            "exec /usr/sbin/sysctl -n hw.machine",
            if cfg!(target_arch = "aarch64") {
                b"arm64\n".as_slice()
            } else {
                b"x86_64\n".as_slice()
            },
        ),
    ] {
        compare_installed_posix_output(
            "darwin",
            "/bin/sh",
            &["-c", command],
            &[("LC_ALL", "C")],
            expected,
        );
    }
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
#[test]
#[ignore = "run explicitly on a glibc distribution with installed ldconfig and cache"]
fn installed_linux_shell_executes_ldconfig_through_closed_c_abi() {
    let ldconfig = ["/usr/sbin/ldconfig", "/sbin/ldconfig"]
        .into_iter()
        .find(|path| std::path::Path::new(path).is_file())
        .expect("installed glibc ldconfig");
    let native = std::process::Command::new(ldconfig)
        .arg("-p")
        .env_clear()
        .env("LC_ALL", "C")
        .output()
        .unwrap();
    assert!(native.status.success());
    assert!(native.stderr.is_empty());
    assert!(String::from_utf8_lossy(&native.stdout).contains("/etc/ld.so.cache"));
    compare_installed_posix_output(
        "linux",
        "/bin/sh",
        &["-c", &format!("exec {ldconfig} -p")],
        &[("LC_ALL", "C")],
        &native.stdout,
    );
}

#[cfg(target_os = "macos")]
#[test]
fn installed_darwin_date_uses_named_timezones_through_closed_c_abi() {
    for (instant, zone, expected) in [
        (
            "1704067200",
            "America/New_York",
            "2023-12-31 19:00:00 EST -0500\n",
        ),
        (
            "1721001600",
            ":/usr/share/zoneinfo/America/New_York",
            "2024-07-14 20:00:00 EDT -0400\n",
        ),
    ] {
        compare_installed_posix_output(
            "darwin",
            "/bin/date",
            &["-r", instant, "+%Y-%m-%d %T %Z %z"],
            &[("LC_ALL", "C"), ("TZ", zone)],
            expected.as_bytes(),
        );
    }
}

#[cfg(target_os = "macos")]
#[test]
fn installed_darwin_df_lists_only_guest_mounts_through_closed_c_abi() {
    let path = "/bin/df";
    let options = serde_json::json!({
        "personality": "darwin",
        "guest_path": path,
        "arguments": ["-n", "-P"],
        "environment": {"LC_ALL": "C"},
        "native_runtime": true,
        "memory_bytes": 268435456,
    });
    let process = open(&std::fs::read(path).unwrap(), &options.to_string());
    let state = info(&process);
    assert_eq!(state["capabilities"]["native_runtime"], true);
    assert_eq!(state["capabilities"]["host_filesystem"], false);
    assert_eq!(state["capabilities"]["host_services"], false);
    let result = run_installed_posix(&process, path);
    assert_eq!(result.exit_code, 0);
    let stdout = capture_installed_posix_stream(&process, RAX_PROCESS_STDOUT);
    let text = std::str::from_utf8(&stdout).unwrap();
    let mut lines = text.lines();
    let header = lines.next().expect("missing df header");
    assert!(header.starts_with("Filesystem"), "{header}");
    let mounts: Vec<_> = lines
        .map(|line| {
            let mut fields = line.split_ascii_whitespace();
            assert_eq!(fields.next(), Some("raxfs"), "{text}");
            fields.last().unwrap()
        })
        .collect();
    assert_eq!(mounts, ["/", "/tmp"], "{text}");
    assert!(capture_installed_posix_stream(&process, RAX_PROCESS_STDERR).is_empty());
}

#[cfg(target_os = "macos")]
#[test]
fn installed_darwin_locales_match_native_through_closed_c_abi() {
    let path = "/usr/bin/locale";
    let native = std::process::Command::new(path)
        .arg("-a")
        .env_clear()
        .env("LC_ALL", "C")
        .output()
        .unwrap();
    assert!(native.status.success());
    assert!(!native.stdout.is_empty());
    let options = serde_json::json!({
        "personality": "darwin",
        "guest_path": path,
        "arguments": ["-a"],
        "environment": {"LC_ALL": "C"},
        "native_runtime": true,
        "memory_bytes": 268435456,
    });
    let process = open(&std::fs::read(path).unwrap(), &options.to_string());
    let state = info(&process);
    assert_eq!(state["capabilities"]["native_runtime"], true);
    assert_eq!(state["capabilities"]["host_filesystem"], false);
    assert_eq!(state["capabilities"]["host_services"], false);
    let result = run_installed_posix(&process, path);
    assert_eq!(result.exit_code, 0);
    let sorted_lines = |bytes: &[u8]| {
        let mut lines: Vec<_> = bytes
            .split_inclusive(|&byte| byte == b'\n')
            .map(<[u8]>::to_vec)
            .collect();
        lines.sort_unstable();
        lines
    };
    // The installed utility preserves the filesystem's directory order.
    let stdout = capture_installed_posix_stream(&process, RAX_PROCESS_STDOUT);
    assert_eq!(sorted_lines(&stdout), sorted_lines(&native.stdout));
    assert_eq!(
        capture_installed_posix_stream(&process, RAX_PROCESS_STDERR),
        native.stderr
    );

    compare_installed_posix_output(
        "darwin",
        path,
        &["-k", "decimal_point"],
        &[("LC_ALL", "fr_FR.UTF-8")],
        b"decimal_point=\",\"\n",
    );
}

#[cfg(target_os = "macos")]
#[test]
fn installed_darwin_reopens_guest_descriptors_through_closed_c_abi() {
    let input = b"guest descriptor input\n";
    for name in ["/dev/stdin", "/dev/fd/0"] {
        compare_installed_posix_with_input("darwin", "/bin/cat", &[name], &[], input, input);
    }
    compare_installed_posix_output(
        "darwin",
        "/bin/sh",
        &[
            "-c",
            "printf '%s\\n' 'guest descriptor output' >/dev/stdout",
        ],
        &[],
        b"guest descriptor output\n",
    );
}

#[cfg(target_os = "macos")]
#[test]
fn installed_darwin_tput_matches_native_through_closed_c_abi() {
    let path = "/usr/bin/tput";
    let environment = &[("LC_ALL", "C")];
    compare_installed_posix_output(
        "darwin",
        path,
        &["-T", "xterm-256color", "colors"],
        environment,
        b"256\n",
    );
    compare_installed_posix_output(
        "darwin",
        path,
        &["-T", "vt100", "clear"],
        environment,
        b"\x1b[H\x1b[J",
    );
}

#[cfg(target_os = "macos")]
#[test]
fn installed_darwin_iconv_matches_native_through_closed_c_abi() {
    let path = "/usr/bin/iconv";
    let environment = &[("LC_ALL", "C")];
    compare_installed_posix_with_input(
        "darwin",
        path,
        &["-f", "UTF-8", "-t", "ISO-8859-1"],
        environment,
        b"caf\xc3\xa9\n",
        b"caf\xe9\n",
    );
    compare_installed_posix_with_input(
        "darwin",
        path,
        &["-f", "WINDOWS-1252", "-t", "UTF-8"],
        environment,
        b"\x80\n",
        b"\xe2\x82\xac\n",
    );
}

#[cfg(target_os = "macos")]
#[test]
fn installed_perl_loads_its_on_disk_dylib_through_closed_c_abi() {
    compare_installed_posix_output(
        "darwin",
        "/usr/bin/perl",
        &["-e", "print qq(installed Perl\\n);"],
        &[],
        b"installed Perl\n",
    );
}

#[cfg(target_os = "macos")]
#[test]
fn installed_sqlite_matches_native_through_closed_c_abi() {
    let path = "/usr/bin/sqlite3";
    let arguments = [
        "-batch",
        "-init",
        "/dev/null",
        "-csv",
        ":memory:",
        "select 'installed sqlite', 6 * 7;",
    ];
    let native = std::process::Command::new(path)
        .args(arguments)
        .env_clear()
        .env("LC_ALL", "C")
        .output()
        .unwrap();
    assert!(native.status.success());
    let native_row = native
        .stdout
        .strip_suffix(b"\r\n")
        .or_else(|| native.stdout.strip_suffix(b"\n"));
    assert_eq!(native_row, Some(b"\"installed sqlite\",42".as_slice()));
    assert!(native.stderr.is_empty());

    let options = serde_json::json!({
        "personality": "darwin",
        "guest_path": path,
        "arguments": arguments,
        "environment": {"LC_ALL": "C"},
        "native_runtime": true,
        "memory_bytes": 268435456,
    });
    let process = open(&std::fs::read(path).unwrap(), &options.to_string());
    let state = info(&process);
    assert_eq!(state["loaded_program"]["has_dyld"], true);
    assert_eq!(state["capabilities"]["native_runtime"], true);
    assert_eq!(state["capabilities"]["host_filesystem"], false);
    assert_eq!(state["capabilities"]["host_services"], false);
    let result = run_installed_posix(&process, path);
    let stdout = capture_installed_posix_stream(&process, RAX_PROCESS_STDOUT);
    let stderr = capture_installed_posix_stream(&process, RAX_PROCESS_STDERR);
    assert_eq!(result.exit_code, 0, "{}", String::from_utf8_lossy(&stderr));
    assert_eq!(stdout, native.stdout);
    assert_eq!(stderr, native.stderr);
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "run with a locally built closed_job_control.c fixture"]
fn installed_darwin_job_control_matches_native_through_closed_c_abi() {
    let path = std::env::var("RAX_DARWIN_INSTALLED_JOB_CONTROL")
        .expect("absolute path to a dynamically linked closed_job_control fixture");
    let architecture = std::env::var("RAX_DARWIN_INSTALLED_JOB_CONTROL_ARCH")
        .expect("fixture architecture: aarch64 or x86_64");
    let native = std::process::Command::new(&path)
        .env_clear()
        .output()
        .unwrap();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(
        native.stdout,
        b"groups, sessions, signals, and post-exec rules match\n"
    );
    assert!(native.stderr.is_empty());

    let image = std::fs::read(&path).unwrap();
    let guest_path = "/closed_job_control";
    let options = serde_json::json!({
        "personality": "darwin",
        "architecture": architecture,
        "guest_path": guest_path,
        "native_runtime": true,
        "memory_bytes": 268435456,
    });
    let process = open(&image, &options.to_string());
    let state = info(&process);
    assert_eq!(state["loaded_program"]["has_dyld"], true);
    assert_eq!(state["capabilities"]["native_runtime"], true);
    assert_eq!(state["capabilities"]["host_filesystem"], false);
    assert_eq!(state["capabilities"]["host_services"], false);
    let status = run_installed_posix_with_turn_limit(&process, guest_path, 65_536);
    let stdout = capture_installed_posix_stream(&process, RAX_PROCESS_STDOUT);
    let stderr = capture_installed_posix_stream(&process, RAX_PROCESS_STDERR);
    assert_eq!(status.exit_code, 0, "{}", String::from_utf8_lossy(&stderr));
    assert_eq!(stdout, native.stdout);
    assert_eq!(stderr, native.stderr);
}

#[cfg(target_os = "linux")]
#[test]
fn installed_cat_reads_guest_null_through_closed_c_abi() {
    compare_installed_posix_output("linux", "/bin/cat", &["/dev/null"], &[], b"");
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "run explicitly with GNU date and installed timezone data"]
fn installed_date_uses_named_timezones_through_closed_c_abi() {
    for (instant, expected) in [
        ("--date=@1704067200", "2023-12-31 19:00:00 EST -0500\n"),
        ("--date=@1721001600", "2024-07-14 20:00:00 EDT -0400\n"),
    ] {
        compare_installed_posix_output(
            "linux",
            "/usr/bin/date",
            &[instant, "+%Y-%m-%d %T %Z %z"],
            &[("LC_ALL", "C"), ("TZ", "America/New_York")],
            expected.as_bytes(),
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "run explicitly with a dynamically linked fixture on Linux"]
fn installed_libc_pipe_matches_native_through_closed_c_abi() {
    let path = std::env::var("RAX_LINUX_INSTALLED_PIPE").expect("path to the pipe fixture");
    let elf = std::fs::read(&path).unwrap();
    let elf = rax_engine::user::image::elf::ElfImage::parse_self_described(&elf).unwrap();
    assert!(
        elf.interpreter().is_some(),
        "fixture must be dynamically linked"
    );
    compare_installed_posix_output(
        "linux",
        &path,
        &[],
        &[],
        b"guest pipe through installed libc\n",
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn installed_head_reads_guest_zero_through_closed_c_abi() {
    let personality = if cfg!(target_os = "linux") {
        "linux"
    } else {
        "darwin"
    };
    compare_installed_posix_output(
        personality,
        "/usr/bin/head",
        &["-c", "16", "/dev/zero"],
        &[],
        &[0; 16],
    );
}

#[cfg(target_os = "linux")]
#[test]
fn installed_shell_replaces_its_image_through_closed_c_abi() {
    let shell = "/bin/sh";
    let target = "/usr/bin/printf";
    let private_target = "/__rax_test_exec__/printf";
    let command = |target: &str| format!(r"exec {target} 'replaced:%s\n' installed-libc");
    let native = std::process::Command::new(shell)
        .arg("-c")
        .arg(command(target))
        .env_clear()
        .env("LC_ALL", "C")
        .output()
        .unwrap();
    assert!(native.status.success());
    assert_eq!(native.stdout, b"replaced:installed-libc\n");
    assert!(native.stderr.is_empty());

    let options = |target| {
        serde_json::json!({
            "personality": "linux",
            "guest_path": shell,
            "arguments": ["-c".to_owned(), command(target)],
            "environment": {"LC_ALL": "C"},
            "native_runtime": true,
            "memory_bytes": 268435456,
        })
        .to_string()
    };
    let shell_image = std::fs::read(shell).unwrap();
    let installed = open(&shell_image, &options(target));
    let private_options = options(private_target);
    let without_target = open(&shell_image, &private_options);
    assert_eq!(run_installed_posix(&without_target, shell).exit_code, 127);
    assert!(capture_installed_posix_stream(&without_target, RAX_PROCESS_STDOUT).is_empty());
    assert_eq!(info(&without_target)["loaded_program"]["path"], shell);

    let next_image = std::fs::read(target).unwrap();
    let supplied = RaxProcessImage {
        path: private_target.as_ptr().cast(),
        path_size: private_target.len(),
        data: next_image.as_ptr(),
        data_size: next_image.len(),
    };
    let mut handle = ptr::null_mut();
    assert_eq!(
        rax_process_open_image(
            shell_image.as_ptr(),
            shell_image.len(),
            private_options.as_ptr().cast(),
            private_options.len(),
            &supplied,
            1,
            &mut handle,
        ),
        RaxStatus::Ok,
        "{}",
        error(),
    );
    assert!(!handle.is_null());
    for (process, expected_path) in [(installed, target), (Owned(handle), private_target)] {
        let start = info(&process);
        assert_eq!(start["loaded_program"]["path"], shell);
        assert_eq!(start["capabilities"]["native_runtime"], true);
        assert_eq!(start["capabilities"]["host_filesystem"], false);
        assert_eq!(start["capabilities"]["host_services"], false);
        let result = run_installed_posix(&process, shell);
        let stdout = capture_installed_posix_stream(&process, RAX_PROCESS_STDOUT);
        let stderr = capture_installed_posix_stream(&process, RAX_PROCESS_STDERR);
        assert_eq!(
            result.exit_code,
            0,
            "{expected_path}: {}",
            String::from_utf8_lossy(&stderr)
        );
        assert_eq!(stdout, native.stdout, "{expected_path}");
        assert_eq!(stderr, native.stderr, "{expected_path}");
        assert_eq!(info(&process)["loaded_program"]["path"], expected_path);
    }
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "run explicitly with a fixture dynamically linked to the installed glibc"]
fn installed_libc_spawn_matches_native_through_closed_c_abi() {
    let path = std::env::var("RAX_LINUX_INSTALLED_SPAWN").expect("path to the spawn fixture");
    let native = std::process::Command::new(&path)
        .env_clear()
        .output()
        .unwrap();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(
        native.stdout,
        b"spawn:installed-libc\nspawn:isolated-group\nmissing:ENOENT\nclone:shared-vm\nclone:shared-files\nclone:shared-fs\nclone:shared-sighand\n"
    );
    assert!(native.stderr.is_empty());

    let child_path = "/usr/bin/printf";
    let child = std::fs::read(child_path).unwrap();
    let image = std::fs::read(&path).unwrap();
    let supplied = RaxProcessImage {
        path: child_path.as_ptr().cast(),
        path_size: child_path.len(),
        data: child.as_ptr(),
        data_size: child.len(),
    };
    let options = serde_json::json!({
        "personality": "linux",
        "guest_path": "/installed-spawn",
        "native_runtime": true,
        "memory_bytes": 268435456,
    })
    .to_string();
    let mut handle = ptr::null_mut();
    assert_eq!(
        rax_process_open_image(
            image.as_ptr(),
            image.len(),
            options.as_ptr().cast(),
            options.len(),
            &supplied,
            1,
            &mut handle,
        ),
        RaxStatus::Ok,
        "{}",
        error(),
    );
    assert!(!handle.is_null());
    let process = Owned(handle);
    let start = info(&process);
    assert_eq!(start["capabilities"]["native_runtime"], true);
    assert_eq!(start["capabilities"]["host_filesystem"], false);
    assert_eq!(start["capabilities"]["host_services"], false);
    let result = run_installed_posix(&process, "/installed-spawn");
    let stdout = capture_installed_posix_stream(&process, RAX_PROCESS_STDOUT);
    let stderr = capture_installed_posix_stream(&process, RAX_PROCESS_STDERR);
    assert_eq!(result.exit_code, 0, "{}", String::from_utf8_lossy(&stderr));
    assert_eq!(stdout, native.stdout);
    assert_eq!(stderr, native.stderr);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn installed_shell_pipeline_matches_native_through_closed_c_abi() {
    let (personality, shell, max_turns) = if cfg!(target_os = "macos") {
        // Bash asks csops for its own image status during Darwin startup.
        ("darwin", "/bin/bash", 131_072)
    } else {
        ("linux", "/bin/sh", 16_384)
    };
    let arguments = [
        "-c",
        r"/usr/bin/printf 'pipeline:%s\n' installed-libc | /bin/cat",
    ];
    let native = std::process::Command::new(shell)
        .args(arguments)
        .env_clear()
        .env("LC_ALL", "C")
        .output()
        .unwrap();
    assert!(native.status.success());
    assert_eq!(native.stdout, b"pipeline:installed-libc\n");
    assert!(native.stderr.is_empty());

    let options = serde_json::json!({
        "personality": personality,
        "guest_path": shell,
        "arguments": arguments,
        "environment": {"LC_ALL": "C"},
        "native_runtime": true,
        "memory_bytes": 268435456,
    })
    .to_string();
    let shell_image = std::fs::read(shell).unwrap();
    let children = ["/usr/bin/printf", "/bin/cat"].map(|path| (path, std::fs::read(path).unwrap()));
    let supplied = children.each_ref().map(|(path, bytes)| RaxProcessImage {
        path: path.as_ptr().cast(),
        path_size: path.len(),
        data: bytes.as_ptr(),
        data_size: bytes.len(),
    });
    let mut handle = ptr::null_mut();
    assert_eq!(
        rax_process_open_image(
            shell_image.as_ptr(),
            shell_image.len(),
            options.as_ptr().cast(),
            options.len(),
            supplied.as_ptr(),
            supplied.len(),
            &mut handle,
        ),
        RaxStatus::Ok,
        "{}",
        error(),
    );
    assert!(!handle.is_null());
    let process = Owned(handle);
    let start = info(&process);
    assert_eq!(start["capabilities"]["native_runtime"], true);
    assert_eq!(start["capabilities"]["host_filesystem"], false);
    assert_eq!(start["capabilities"]["host_services"], false);
    let result = run_installed_posix_with_turn_limit(&process, shell, max_turns);
    let stdout = capture_installed_posix_stream(&process, RAX_PROCESS_STDOUT);
    let stderr = capture_installed_posix_stream(&process, RAX_PROCESS_STDERR);
    assert_eq!(result.exit_code, 0, "{}", String::from_utf8_lossy(&stderr));
    assert_eq!(stdout, native.stdout);
    assert_eq!(stderr, native.stderr);
    assert_eq!(info(&process)["loaded_program"]["path"], shell);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
#[ignore = "run with the host shell and tar using an isolated test directory"]
fn installed_tar_preserves_workspace_links_through_closed_c_abi() {
    let (personality, shell) = if cfg!(target_os = "macos") {
        ("darwin", "/bin/bash")
    } else {
        ("linux", "/bin/sh")
    };
    let commands = ["/bin/mkdir", "/bin/ln", "/usr/bin/tar"];
    let script = r#"
set -eu
umask 077
/bin/mkdir "$1" "$1/input" "$1/output"
cd "$1"
printf 'archive:installed-libc\n' >input/primary
/bin/ln input/primary input/alias
/bin/ln -s primary input/symbol
/usr/bin/tar --format ustar -cf payload.tar -C input primary alias symbol
/usr/bin/tar --no-same-owner -xf payload.tar -C output
test output/primary -ef output/alias
test -L output/symbol
IFS= read -r line <output/symbol
printf '%s\n' "$line"
"#;
    let environment = [("LC_ALL", "C"), ("COPYFILE_DISABLE", "1")];
    let native_root =
        std::env::temp_dir().join(format!("rax-installed-tar-{}", std::process::id()));
    std::fs::create_dir(&native_root).unwrap();
    #[cfg(target_os = "macos")]
    let architecture = std::env::var("RAX_POSIX_INSTALLED_DIRECTORY_CONTROL_ARCH")
        .unwrap_or_else(|_| std::env::consts::ARCH.to_owned());
    #[cfg(target_os = "macos")]
    let mut native_shell = {
        let flag = match architecture.as_str() {
            "aarch64" => "-arm64",
            "x86_64" => "-x86_64",
            other => panic!("unexpected installed Darwin architecture {other}"),
        };
        let mut command = std::process::Command::new("/usr/bin/arch");
        command.args([flag, shell]);
        command
    };
    #[cfg(target_os = "linux")]
    let mut native_shell = std::process::Command::new(shell);
    let native = native_shell
        .args(["-c", script, shell])
        .arg(native_root.join("control"))
        .env_clear()
        .envs(environment)
        .output();
    std::fs::remove_dir_all(&native_root).unwrap();
    let native = native.unwrap();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(native.stdout, b"archive:installed-libc\n");
    assert!(native.stderr.is_empty());

    let options = serde_json::json!({
        "personality": personality,
        "guest_path": shell,
        "arguments": ["-c", script, shell, "/tmp/installed-tar"],
        "environment": environment.into_iter().collect::<std::collections::BTreeMap<_, _>>(),
        "native_runtime": true,
        "memory_bytes": 268435456,
    });
    #[cfg(target_os = "macos")]
    let options = {
        let mut options = options;
        options["architecture"] = architecture.as_str().into();
        options
    };
    let options = options.to_string();
    let shell_image = std::fs::read(shell).unwrap();
    let children = commands.map(|path| (path, std::fs::read(path).unwrap()));
    let supplied = children.each_ref().map(|(path, bytes)| RaxProcessImage {
        path: path.as_ptr().cast(),
        path_size: path.len(),
        data: bytes.as_ptr(),
        data_size: bytes.len(),
    });
    let mut handle = ptr::null_mut();
    assert_eq!(
        rax_process_open_image(
            shell_image.as_ptr(),
            shell_image.len(),
            options.as_ptr().cast(),
            options.len(),
            supplied.as_ptr(),
            supplied.len(),
            &mut handle,
        ),
        RaxStatus::Ok,
        "{}",
        error(),
    );
    assert!(!handle.is_null());
    let process = Owned(handle);
    let start = info(&process);
    #[cfg(target_os = "macos")]
    assert_eq!(start["architecture"], architecture);
    assert_eq!(start["capabilities"]["native_runtime"], true);
    assert_eq!(start["capabilities"]["host_filesystem"], false);
    assert_eq!(start["capabilities"]["host_services"], false);
    let result = run_installed_posix_with_turn_limit(&process, shell, 131_072);
    let stdout = capture_installed_posix_stream(&process, RAX_PROCESS_STDOUT);
    let stderr = capture_installed_posix_stream(&process, RAX_PROCESS_STDERR);
    assert_eq!(result.exit_code, 0, "{}", String::from_utf8_lossy(&stderr));
    assert_eq!(stdout, native.stdout);
    assert_eq!(stderr, native.stderr);
}

#[cfg(target_os = "macos")]
#[test]
fn installed_darwin_sh_selects_a_supplied_variant_through_closed_c_abi() {
    let shell = "/bin/sh";
    let selector = "/private/var/select/sh";
    let selected = std::fs::read_link(selector).ok();
    let variant = match selected.as_deref().and_then(std::path::Path::to_str) {
        Some(path @ ("/bin/dash" | "/bin/zsh")) => path,
        _ => "/bin/bash",
    };
    let arguments = ["-c", r"printf 'selected shell:%s\n' installed"];
    let native = std::process::Command::new(shell)
        .args(arguments)
        .env_clear()
        .env("LC_ALL", "C")
        .output()
        .unwrap();
    assert!(native.status.success());
    assert_eq!(native.stdout, b"selected shell:installed\n");
    assert!(native.stderr.is_empty());

    let options = serde_json::json!({
        "personality": "darwin",
        "guest_path": shell,
        "arguments": arguments,
        "environment": {"LC_ALL": "C"},
        "native_runtime": true,
        "memory_bytes": 268435456,
    })
    .to_string();
    let image = std::fs::read(shell).unwrap();
    let variant_image = std::fs::read(variant).unwrap();
    let supplied = RaxProcessImage {
        path: variant.as_ptr().cast(),
        path_size: variant.len(),
        data: variant_image.as_ptr(),
        data_size: variant_image.len(),
    };
    let mut handle = ptr::null_mut();
    assert_eq!(
        rax_process_open_image(
            image.as_ptr(),
            image.len(),
            options.as_ptr().cast(),
            options.len(),
            &supplied,
            1,
            &mut handle,
        ),
        RaxStatus::Ok,
        "{}",
        error()
    );
    assert!(!handle.is_null());
    let process = Owned(handle);
    let start = info(&process);
    assert_eq!(start["capabilities"]["native_runtime"], true);
    assert_eq!(start["capabilities"]["host_filesystem"], false);
    assert_eq!(start["capabilities"]["host_services"], false);
    let result = run_installed_posix_with_turn_limit(&process, shell, 131_072);
    let stdout = capture_installed_posix_stream(&process, RAX_PROCESS_STDOUT);
    let stderr = capture_installed_posix_stream(&process, RAX_PROCESS_STDERR);
    assert_eq!(result.exit_code, 0, "{}", String::from_utf8_lossy(&stderr));
    assert_eq!(stdout, native.stdout);
    assert_eq!(stderr, native.stderr);
    assert_eq!(info(&process)["loaded_program"]["path"], variant);

    // A valid installed link must be visible even if no shell image was supplied.
    if matches!(
        selected.as_deref().and_then(std::path::Path::to_str),
        Some("/bin/bash" | "/bin/dash" | "/bin/zsh")
    ) {
        let mut target = variant.as_bytes().to_vec();
        target.push(b'\n');
        compare_installed_posix_output("darwin", "/usr/bin/readlink", &[selector], &[], &target);
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn installed_gzip_matches_native_binary_output_through_closed_c_abi() {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let path = "/usr/bin/gzip";
    let arguments = ["-n", "-c"];
    let input =
        b"closed installed runtime\ngzip stock gzip stock gzip stock\n\x00\x01\x02\x03 end\n";
    let mut native = Command::new(path)
        .args(arguments)
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    native.stdin.take().unwrap().write_all(input).unwrap();
    let native = native.wait_with_output().unwrap();
    assert!(native.status.success());
    assert!(native.stderr.is_empty());
    assert!(native.stdout.starts_with(&[0x1f, 0x8b, 0x08]));

    let personality = if cfg!(target_os = "linux") {
        "linux"
    } else {
        "darwin"
    };
    let options = serde_json::json!({
        "personality": personality,
        "guest_path": path,
        "arguments": arguments,
        "environment": {"LC_ALL": "C"},
        "native_runtime": true,
        "memory_bytes": 268435456,
    });
    let process = open(&std::fs::read(path).unwrap(), &options.to_string());
    let state = info(&process);
    assert_eq!(state["capabilities"]["native_runtime"], true);
    assert_eq!(state["capabilities"]["host_filesystem"], false);
    assert_eq!(state["capabilities"]["host_services"], false);
    assert_eq!(
        rax_process_stdin_feed(process.0, input.as_ptr(), input.len()),
        RaxStatus::Ok
    );
    assert_eq!(run_installed_posix(&process, path).exit_code, 0);
    assert_eq!(
        capture_installed_posix_stream(&process, RAX_PROCESS_STDOUT),
        native.stdout
    );
    assert_eq!(
        capture_installed_posix_stream(&process, RAX_PROCESS_STDERR),
        native.stderr
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn installed_mktemp_creates_a_guest_owned_regular_file() {
    let path = "/usr/bin/mktemp";
    let prefix = format!("/tmp/.rax-closed-mktemp-{}-", std::process::id());
    let template = format!("{prefix}XXXXXX");
    let installed_image = std::fs::read(path).unwrap();
    let personality = if cfg!(target_os = "linux") {
        "linux"
    } else {
        "darwin"
    };
    for _ in 0..2 {
        let options = serde_json::json!({
            "personality": personality,
            "guest_path": path,
            "arguments": [&template],
            "environment": {"LC_ALL": "C"},
            "native_runtime": true,
            "memory_bytes": 268435456,
        });
        let process = open(&installed_image, &options.to_string());
        let state = info(&process);
        assert_eq!(state["capabilities"]["native_runtime"], true);
        assert_eq!(state["capabilities"]["host_filesystem"], false);
        assert_eq!(state["capabilities"]["host_services"], false);
        let result = run_installed_posix(&process, path);
        let stderr = capture_installed_posix_stream(&process, RAX_PROCESS_STDERR);
        assert_eq!(result.exit_code, 0, "{}", String::from_utf8_lossy(&stderr));
        assert!(stderr.is_empty());
        let stdout = capture_installed_posix_stream(&process, RAX_PROCESS_STDOUT);
        let reported = std::str::from_utf8(&stdout)
            .unwrap()
            .strip_suffix('\n')
            .unwrap();
        let suffix = reported.strip_prefix(&prefix).unwrap();
        assert_eq!(suffix.len(), 6);
        assert!(suffix.bytes().all(|byte| byte.is_ascii_alphanumeric()));
        assert!(!std::path::Path::new(reported).exists(), "{reported}");
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn installed_mktemp_and_mkdir_create_guest_owned_directories() {
    let (personality, mkdir) = if cfg!(target_os = "linux") {
        ("linux", "/usr/bin/mkdir")
    } else {
        ("darwin", "/bin/mkdir")
    };
    let root = format!("/tmp/.rax-closed-directories-{}", std::process::id());
    let prefix = format!("{root}-");
    let template = format!("{prefix}XXXXXX");
    let nested = format!("{root}/first/second");
    for (program, arguments) in [
        ("/usr/bin/mktemp", ["-d", &template]),
        (mkdir, ["-p", &nested]),
    ] {
        let options = serde_json::json!({
            "personality": personality,
            "guest_path": program,
            "arguments": arguments,
            "environment": {"LC_ALL": "C"},
            "native_runtime": true,
            "memory_bytes": 268435456,
        });
        let process = open(&std::fs::read(program).unwrap(), &options.to_string());
        let status = run_installed_posix(&process, program);
        let stderr = capture_installed_posix_stream(&process, RAX_PROCESS_STDERR);
        assert_eq!(status.exit_code, 0, "{}", String::from_utf8_lossy(&stderr));
        assert!(stderr.is_empty());
        let stdout = capture_installed_posix_stream(&process, RAX_PROCESS_STDOUT);
        if program == mkdir {
            assert!(stdout.is_empty());
            assert!(!std::path::Path::new(&root).exists());
        } else {
            let reported = std::str::from_utf8(&stdout)
                .unwrap()
                .strip_suffix('\n')
                .unwrap();
            let suffix = reported.strip_prefix(&prefix).unwrap();
            assert_eq!(suffix.len(), 6);
            assert!(suffix.bytes().all(|byte| byte.is_ascii_alphanumeric()));
            assert!(!std::path::Path::new(reported).exists());
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
#[ignore = "run with a locally built closed_directory_listing.c fixture"]
fn installed_libc_directory_listing_matches_native_through_closed_c_abi() {
    let binary = std::env::var("RAX_POSIX_INSTALLED_DIRECTORY_CONTROL")
        .expect("absolute path to the dynamically linked closed_directory_listing fixture");
    compare_installed_workspace_fixture(
        &binary,
        "closed_directory_listing",
        Some(b"directory creation, listing, removal, and retained handles: correct\n"),
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
#[ignore = "run with a locally built closed_directory_rename.c fixture"]
fn installed_libc_directory_rename_matches_native_through_closed_c_abi() {
    let binary = std::env::var("RAX_POSIX_INSTALLED_RENAME_CONTROL")
        .expect("absolute path to the dynamically linked closed_directory_rename fixture");
    compare_installed_workspace_fixture(&binary, "closed_directory_rename", None);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
#[ignore = "run with a locally built closed_workspace_symlink.c fixture"]
fn installed_libc_workspace_symlinks_match_native_through_closed_c_abi() {
    let binary = std::env::var("RAX_POSIX_INSTALLED_SYMLINK_CONTROL")
        .expect("absolute path to the dynamically linked closed_workspace_symlink fixture");
    compare_installed_workspace_fixture(&binary, "closed_workspace_symlink", None);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
#[ignore = "run with a locally built closed_workspace_hardlink.c fixture"]
fn installed_libc_workspace_hardlinks_match_native_through_closed_c_abi() {
    let binary = std::env::var("RAX_POSIX_INSTALLED_HARDLINK_CONTROL")
        .expect("absolute path to the dynamically linked closed_workspace_hardlink fixture");
    compare_installed_workspace_fixture(&binary, "closed_workspace_hardlink", None);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
#[ignore = "run with a locally built closed_workspace_statfs.c fixture"]
fn installed_libc_workspace_statfs_matches_native_through_closed_c_abi() {
    let binary = std::env::var("RAX_POSIX_INSTALLED_STATFS_CONTROL")
        .expect("absolute path to the dynamically linked closed_workspace_statfs fixture");
    compare_installed_workspace_fixture(&binary, "closed_workspace_statfs", None);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
#[ignore = "run with a locally built closed_workspace_metadata.c fixture"]
fn installed_libc_workspace_metadata_matches_native_through_closed_c_abi() {
    let binary = std::env::var("RAX_POSIX_INSTALLED_METADATA_CONTROL")
        .expect("absolute path to the dynamically linked closed_workspace_metadata fixture");
    compare_installed_workspace_fixture(&binary, "closed_workspace_metadata", None);
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "run with a locally built closed_workspace_pathconf.c fixture on APFS"]
fn installed_libc_workspace_pathconf_matches_native_through_closed_c_abi() {
    let binary = std::env::var("RAX_POSIX_INSTALLED_PATHCONF_CONTROL")
        .expect("absolute path to the dynamically linked closed_workspace_pathconf fixture");
    compare_installed_workspace_fixture(&binary, "closed_workspace_pathconf", None);
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "run with a locally built closed_workspace_search.c fixture"]
fn installed_libc_workspace_search_matches_native_through_closed_c_abi() {
    let binary = std::env::var("RAX_POSIX_INSTALLED_SEARCH_CONTROL")
        .expect("absolute path to the dynamically linked closed_workspace_search fixture");
    compare_installed_workspace_fixture(&binary, "closed_workspace_search", None);
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "run with a locally built closed_workspace_xattr_list.c fixture"]
fn installed_libc_workspace_xattr_list_matches_native_through_closed_c_abi() {
    let binary = std::env::var("RAX_POSIX_INSTALLED_XATTR_LIST_CONTROL")
        .expect("absolute path to the dynamically linked closed_workspace_xattr_list fixture");
    compare_installed_workspace_fixture(&binary, "closed_workspace_xattr_list", None);
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "run with a locally built closed_workspace_xattr_values.c fixture on APFS"]
fn installed_libc_workspace_xattr_values_match_native_through_closed_c_abi() {
    let binary = std::env::var("RAX_POSIX_INSTALLED_XATTR_VALUES_CONTROL")
        .expect("absolute path to the dynamically linked closed_workspace_xattr_values fixture");
    compare_installed_workspace_fixture(&binary, "closed_workspace_xattr_values", None);
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "run with a locally built closed_workspace_filesec.c fixture on APFS"]
fn installed_darwin_workspace_filesec_matches_native_through_closed_c_abi() {
    let binary = std::env::var("RAX_DARWIN_INSTALLED_FILESEC_CONTROL")
        .expect("absolute path to the dynamically linked closed_workspace_filesec fixture");
    compare_installed_workspace_fixture(&binary, "closed_workspace_filesec", None);
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "run with a locally built closed_darwin_workspace_resource_fork.c fixture on APFS"]
fn installed_darwin_resource_fork_matches_native_through_closed_c_abi() {
    let binary = std::env::var("RAX_DARWIN_INSTALLED_RESOURCE_FORK_CONTROL")
        .expect("absolute path to the dynamically linked resource fork fixture");
    compare_installed_workspace_fixture(&binary, "closed_darwin_workspace_resource_fork", None);
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "requires the locally built closed_darwin_workspace_record_locks.c APFS fixture"]
fn installed_darwin_record_locks_match_native_through_closed_c_abi() {
    let binary = std::env::var("RAX_DARWIN_INSTALLED_RECORD_LOCK_CONTROL")
        .expect("absolute path to the dynamically linked record lock fixture");
    // This fixture starts dyld again for each of the exec and spawn controls.
    compare_installed_workspace_fixture_with_turn_limit(
        &binary,
        "closed_darwin_workspace_record_locks",
        None,
        131_072,
    );
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "requires the locally built closed_darwin_workspace_blocking_locks.c APFS fixture"]
fn installed_darwin_blocking_locks_match_native_through_closed_c_abi() {
    let binary = std::env::var("RAX_DARWIN_INSTALLED_BLOCKING_LOCK_CONTROL")
        .expect("absolute path to the dynamically linked blocking lock fixture");
    let expected = concat!(
        "uncontended\n",
        "released by unlock\n",
        "released by close\n",
        "released by exit\n",
        "interrupted by signal\n",
        "restarted by signal\n",
        "one deadlock rejected\n",
    );
    compare_installed_workspace_fixture(
        &binary,
        "closed_darwin_workspace_blocking_locks",
        Some(expected.as_bytes()),
    );
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "run with a locally built closed_linux_workspace_xattr.c fixture on a user-xattr filesystem"]
fn installed_linux_workspace_xattrs_match_native_through_closed_c_abi() {
    let binary = std::env::var("RAX_LINUX_INSTALLED_XATTR_CONTROL")
        .expect("absolute path to the dynamically linked closed_linux_workspace_xattr fixture");
    compare_installed_workspace_fixture(&binary, "closed_linux_workspace_xattr", None);
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires a locally built closed_linux_workspace_record_locks.c fixture"]
fn installed_linux_workspace_record_locks_match_native_through_closed_c_abi() {
    let binary = std::env::var("RAX_LINUX_INSTALLED_RECORD_LOCK_CONTROL")
        .expect("absolute path to the dynamically linked Linux record lock fixture");
    let expected = concat!(
        "POSIX hard link and close\n",
        "OFD sharing and last close\n",
        "POSIX deadlock rejection\n",
        "POSIX signal interruption\n",
    );
    compare_installed_workspace_fixture(
        &binary,
        "closed_linux_workspace_record_locks",
        Some(expected.as_bytes()),
    );
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires a locally built closed_linux_workspace_flock.c fixture"]
fn installed_linux_workspace_flock_matches_native_through_closed_c_abi() {
    let binary = std::env::var("RAX_LINUX_INSTALLED_FLOCK_CONTROL")
        .expect("absolute path to the dynamically linked Linux flock fixture");
    let expected = concat!(
        "whole-file lock owner and conversion\n",
        "whole-file lock wakes on last close\n",
    );
    compare_installed_workspace_fixture(
        &binary,
        "closed_linux_workspace_flock",
        Some(expected.as_bytes()),
    );
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "requires a locally built closed_darwin_workspace_flock.c fixture"]
fn installed_darwin_workspace_flock_matches_native_through_closed_c_abi() {
    let binary = std::env::var("RAX_DARWIN_INSTALLED_FLOCK_CONTROL")
        .expect("absolute path to the dynamically linked Darwin flock fixture");
    let expected = concat!(
        "APFS whole-file and record lock interaction\n",
        "APFS lock inheritance and wake on owner exit\n",
        "APFS directory and resource-fork lock identity\n",
    );
    compare_installed_workspace_fixture(
        &binary,
        "closed_darwin_workspace_flock",
        Some(expected.as_bytes()),
    );
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "requires a locally built closed_darwin_workspace_open_locks.c fixture"]
fn installed_darwin_workspace_open_locks_match_native_through_closed_c_abi() {
    let binary = std::env::var("RAX_DARWIN_INSTALLED_OPEN_LOCK_CONTROL")
        .expect("absolute path to the dynamically linked Darwin open lock fixture");
    let expected = concat!(
        "open locks share vnode identity and protect truncation\n",
        "blocking open truncates after the owner releases its lock\n",
        "interrupted open releases its reserved descriptor\n",
        "directory and resource fork use their own open locks\n",
    );
    compare_installed_workspace_fixture(
        &binary,
        "closed_darwin_workspace_open_locks",
        Some(expected.as_bytes()),
    );
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "requires a locally built closed_darwin_workspace_clonefile.c fixture on APFS"]
fn installed_darwin_workspace_clonefile_matches_native_through_closed_c_abi() {
    let binary = std::env::var("RAX_DARWIN_INSTALLED_CLONEFILE_CONTROL")
        .expect("absolute path to the dynamically linked Darwin clonefile fixture");
    compare_installed_workspace_fixture(&binary, "closed_darwin_workspace_clonefile", None);
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "requires a locally built closed_darwin_spawn_open_locks.c fixture"]
fn installed_darwin_spawn_open_locks_match_native_through_closed_c_abi() {
    let binary = std::env::var("RAX_DARWIN_INSTALLED_SPAWN_OPEN_LOCK_CONTROL")
        .expect("absolute path to the dynamically linked Darwin spawn open lock fixture");
    let expected = concat!(
        "spawn open reports a nonblocking conflict and preserves truncation order\n",
        "blocking spawn preserves earlier actions and passes the lock to its child\n",
        "interrupted spawn leaves the locked file untruncated\n",
    );
    compare_installed_workspace_fixture_with_turn_limit(
        &binary,
        "closed_darwin_spawn_open_locks",
        Some(expected.as_bytes()),
        65_536,
    );
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "run with a locally built and ad hoc signed closed_csops_empty.c fixture"]
fn installed_libc_empty_entitlements_match_native_through_closed_c_abi() {
    let binary = std::env::var("RAX_DARWIN_CSOPS_EMPTY_CONTROL")
        .expect("absolute path to the signed closed_csops_empty fixture");
    compare_installed_workspace_fixture(&binary, "closed_csops_empty", None);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn compare_installed_workspace_fixture(
    binary: &str,
    fixture: &str,
    expected_stdout: Option<&[u8]>,
) {
    compare_installed_workspace_fixture_with_turn_limit(
        binary,
        fixture,
        expected_stdout,
        INSTALLED_POSIX_DEFAULT_TURNS,
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn compare_installed_workspace_fixture_with_turn_limit(
    binary: &str,
    fixture: &str,
    expected_stdout: Option<&[u8]>,
    max_turns: u64,
) {
    let native_path = std::env::temp_dir().join(format!("rax-{fixture}-{}", std::process::id()));
    std::fs::create_dir(&native_path).unwrap();
    let native = std::process::Command::new(&binary)
        .arg(native_path.join("control"))
        .env_clear()
        .output();
    std::fs::remove_dir_all(&native_path).unwrap();
    let native = native.unwrap();
    assert!(
        native.status.success(),
        "{}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert!(native.stderr.is_empty());
    assert!(!native.stdout.is_empty());
    if let Some(expected) = expected_stdout {
        assert_eq!(native.stdout, expected);
    }

    let personality = if cfg!(target_os = "linux") {
        "linux"
    } else {
        "darwin"
    };
    let guest_path = format!("/{fixture}");
    let options = serde_json::json!({
        "personality": personality,
        "guest_path": guest_path,
        "arguments": [format!("/tmp/{fixture}")],
        "native_runtime": true,
        "memory_bytes": 268435456,
    });
    #[cfg(target_os = "macos")]
    let options = {
        let architecture = std::env::var("RAX_POSIX_INSTALLED_DIRECTORY_CONTROL_ARCH")
            .expect("fixture architecture: aarch64 or x86_64");
        let mut options = options;
        options["architecture"] = architecture.into();
        options
    };
    let process = open(&std::fs::read(&binary).unwrap(), &options.to_string());
    let state = info(&process);
    assert_eq!(state["capabilities"]["native_runtime"], true);
    assert_eq!(state["capabilities"]["host_filesystem"], false);
    assert_eq!(state["capabilities"]["host_services"], false);
    let status = run_installed_posix_with_turn_limit(&process, &guest_path, max_turns);
    let stdout = capture_installed_posix_stream(&process, RAX_PROCESS_STDOUT);
    let stderr = capture_installed_posix_stream(&process, RAX_PROCESS_STDERR);
    assert_eq!(status.exit_code, 0, "{}", String::from_utf8_lossy(&stderr));
    assert_eq!(stdout, native.stdout);
    assert_eq!(stderr, native.stderr);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn compare_installed_posix_output(
    personality: &str,
    path: &str,
    arguments: &[&str],
    environment: &[(&str, &str)],
    expected_stdout: &[u8],
) {
    compare_installed_posix_with_input(
        personality,
        path,
        arguments,
        environment,
        b"",
        expected_stdout,
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn compare_installed_posix_with_input(
    personality: &str,
    path: &str,
    arguments: &[&str],
    environment: &[(&str, &str)],
    input: &[u8],
    expected_stdout: &[u8],
) {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let mut command = Command::new(path);
    command
        .args(arguments)
        .env_clear()
        .envs(environment.iter().copied());
    let native = if input.is_empty() {
        command.output().unwrap()
    } else {
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(input).unwrap();
        child.wait_with_output().unwrap()
    };
    assert!(native.status.success());
    assert_eq!(native.stdout, expected_stdout);
    assert!(native.stderr.is_empty());

    let options = serde_json::json!({
        "personality": personality,
        "guest_path": path,
        "arguments": arguments,
        "environment": environment.iter().copied().collect::<std::collections::BTreeMap<_, _>>(),
        "native_runtime": true,
        "memory_bytes": 268435456,
    });
    let process = open(&std::fs::read(path).unwrap(), &options.to_string());
    if !input.is_empty() {
        assert_eq!(
            rax_process_stdin_feed(process.0, input.as_ptr(), input.len()),
            RaxStatus::Ok
        );
    }
    let state = info(&process);
    assert_eq!(state["capabilities"]["native_runtime"], true);
    assert_eq!(state["capabilities"]["host_filesystem"], false);
    assert_eq!(state["capabilities"]["host_services"], false);
    let result = run_installed_posix(&process, path);
    let stdout = capture_installed_posix_stream(&process, RAX_PROCESS_STDOUT);
    let stderr = capture_installed_posix_stream(&process, RAX_PROCESS_STDERR);
    assert_eq!(result.exit_code, 0, "{}", String::from_utf8_lossy(&stderr));
    assert_eq!(stdout, native.stdout);
    assert_eq!(stderr, native.stderr);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
const INSTALLED_POSIX_DEFAULT_TURNS: u64 = 16_384;

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn run_installed_posix(process: &Owned, path: &str) -> RaxProcessResult {
    run_installed_posix_with_turn_limit(process, path, INSTALLED_POSIX_DEFAULT_TURNS)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn run_installed_posix_with_turn_limit(
    process: &Owned,
    path: &str,
    max_turns: u64,
) -> RaxProcessResult {
    let mut remaining = max_turns;
    let mut result = RaxProcessResult::default();
    loop {
        assert!(
            remaining != 0,
            "{path}: exceeded {max_turns} scheduler turns: {}",
            info(process)
        );
        let turns = remaining.min(256);
        assert_eq!(
            rax_process_run(process.0, turns, 0, &mut result),
            RaxStatus::Ok
        );
        assert!(result.turns_started <= turns);
        remaining -= result.turns_started;
        if result.reason != RAX_PROCESS_BUDGET {
            break;
        }
        assert_ne!(result.turns_started, 0, "{path}: budget made no progress");
    }
    eprintln!(
        "{path}: completed within {} scheduler turns",
        max_turns - remaining
    );
    if result.reason != RAX_PROCESS_EXITED {
        let state = info(process);
        let fault = super::darwin::fault_snapshot(process, &state);
        panic!(
            "{path}: terminal reason {}, state {state}; fault {fault:?}",
            result.reason
        );
    }
    result
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
#[ignore = "run explicitly with the Linux x64 CI multilib program and installed i386 libc"]
fn installed_i386_glibc_matches_native_through_closed_c_abi() {
    let path = std::env::var("RAX_LINUX_MULTILIB_PROGRAM").expect("path to the i386 fixture");
    let image = std::fs::read(&path).expect("read i386 fixture");
    let elf = rax_engine::user::image::elf::ElfImage::parse_self_described(&image).unwrap();
    assert_eq!(elf.interpreter(), Some(b"/lib/ld-linux.so.2".as_slice()));
    let loader = std::fs::canonicalize("/lib/ld-linux.so.2").expect("installed i386 loader");
    assert!(
        loader.starts_with("/lib32") || loader.starts_with("/usr/lib32"),
        "expected a biarch glibc loader under lib32, got {loader:?}"
    );
    let native = std::process::Command::new(&path)
        .env_clear()
        .output()
        .expect("run the i386 fixture natively");
    assert_eq!(native.status.code(), Some(23));
    assert_eq!(native.stdout, b"installed i386 libc\n");
    assert!(native.stderr.is_empty());

    let mut options = serde_json::json!({
        "personality": "linux",
        "native_runtime": true,
        "memory_bytes": 268435456,
        "slice_instructions": 4096,
    });
    let process = open(&image, &options.to_string());
    let before = info(&process);
    assert_eq!(before["architecture"], "x86");
    assert_eq!(before["capabilities"]["native_runtime"], true);
    assert_eq!(before["capabilities"]["host_filesystem"], false);
    assert_eq!(before["capabilities"]["host_services"], false);
    let exit_code = run_installed_posix(&process, &path).exit_code;
    let stdout = capture_installed_posix_stream(&process, RAX_PROCESS_STDOUT);
    let stderr = capture_installed_posix_stream(&process, RAX_PROCESS_STDERR);
    if exit_code != 23 {
        let library_dir = loader.parent().unwrap();
        for environment in [
            serde_json::json!({"LD_DEBUG": "libs,files"}),
            serde_json::json!({"LD_DEBUG": "libs,files", "LD_LIBRARY_PATH": library_dir}),
        ] {
            options["environment"] = environment;
            let traced = open(&image, &options.to_string());
            let status = run_installed_posix(&traced, &path);
            let trace = capture_installed_posix_stream(&traced, RAX_PROCESS_STDERR);
            eprintln!(
                "i386 loader trace with {} (exit {}):\n{}",
                options["environment"],
                status.exit_code,
                String::from_utf8_lossy(&trace)
            );
        }
    }
    assert_eq!(
        exit_code,
        23,
        "i386 guest stderr: {}",
        String::from_utf8_lossy(&stderr)
    );
    assert_eq!(stdout, native.stdout);
    assert_eq!(stderr, native.stderr);
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
#[ignore = "run explicitly with the Linux x64 CI program and installed musl"]
fn installed_musl_matches_native_through_closed_c_abi() {
    let path = std::env::var("RAX_LINUX_MUSL_PROGRAM").expect("path to the musl fixture");
    let image = std::fs::read(&path).expect("read the dynamically linked musl fixture");
    let elf = rax_engine::user::image::elf::ElfImage::parse_self_described(&image).unwrap();
    let interpreter = "/lib/ld-musl-x86_64.so.1";
    assert_eq!(elf.interpreter(), Some(interpreter.as_bytes()));
    let loader = std::fs::canonicalize(interpreter).expect("installed musl loader");
    assert!(loader.is_file(), "{loader:?}");

    let native = std::process::Command::new(&path)
        .env_clear()
        .output()
        .expect("run the musl fixture natively");
    assert_eq!(native.status.code(), Some(24));
    assert_eq!(native.stdout, b"installed musl libc\n");
    assert!(native.stderr.is_empty());

    let options = serde_json::json!({
        "personality": "linux",
        "native_runtime": true,
        "memory_bytes": 268435456,
        "slice_instructions": 4096,
    });
    let process = open(&image, &options.to_string());
    let before = info(&process);
    assert_eq!(before["architecture"], "x86_64");
    assert_eq!(before["capabilities"]["native_runtime"], true);
    assert_eq!(before["capabilities"]["host_filesystem"], false);
    assert_eq!(before["capabilities"]["host_services"], false);
    let exit_code = run_installed_posix(&process, &path).exit_code;
    let stdout = capture_installed_posix_stream(&process, RAX_PROCESS_STDOUT);
    let stderr = capture_installed_posix_stream(&process, RAX_PROCESS_STDERR);
    assert_eq!(
        exit_code,
        24,
        "musl guest stderr: {}",
        String::from_utf8_lossy(&stderr)
    );
    assert_eq!(stdout, native.stdout);
    assert_eq!(stderr, native.stderr);
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[test]
#[ignore = "run explicitly with the distribution's installed Python"]
fn installed_system_python_matches_native_through_closed_c_abi() {
    let path = std::env::var("RAX_LINUX_SYSTEM_PYTHON")
        .expect("path to the distribution's installed Python");
    let image = std::fs::read(&path).expect("installed Python image");
    let elf = rax_engine::user::image::elf::ElfImage::parse_self_described(&image).unwrap();
    assert!(
        elf.interpreter().is_some(),
        "Python must be dynamically linked"
    );
    let script = r#"import _sqlite3, json, math, sqlite3, zlib
assert _sqlite3.__file__.endswith(".so")
assert sqlite3.connect(":memory:").execute("select 6 * 7").fetchone() == (42,)
payload = b"installed python libraries"
restored = zlib.decompress(zlib.compress(payload))
print(json.dumps({"root": math.isqrt(1764), "round_trip": restored.decode("ascii")}, sort_keys=True))
"#;
    let arguments = ["-I", "-S", "-c", script];
    let native = std::process::Command::new(&path)
        .args(arguments)
        .env_clear()
        .output()
        .unwrap();
    assert!(
        native.status.success(),
        "native Python stderr: {}",
        String::from_utf8_lossy(&native.stderr)
    );
    assert_eq!(
        native.stdout,
        b"{\"root\": 42, \"round_trip\": \"installed python libraries\"}\n",
    );
    assert!(native.stderr.is_empty());
    let options = serde_json::json!({
        "personality": "linux",
        "guest_path": path,
        "arguments": arguments,
        "native_runtime": true,
        "memory_bytes": 268435456,
    });
    let process = open(&image, &options.to_string());
    let state = info(&process);
    assert_eq!(state["capabilities"]["native_runtime"], true);
    assert_eq!(state["capabilities"]["host_filesystem"], false);
    assert_eq!(state["capabilities"]["host_services"], false);
    // Allow enough slices for Python startup and extension loading.
    let result = run_installed_posix_with_turn_limit(&process, &path, 131_072);
    let stdout = capture_installed_posix_stream(&process, RAX_PROCESS_STDOUT);
    let stderr = capture_installed_posix_stream(&process, RAX_PROCESS_STDERR);
    assert_eq!(result.exit_code, 0, "{}", String::from_utf8_lossy(&stderr));
    assert_eq!(stdout, native.stdout);
    assert_eq!(stderr, native.stderr);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn capture_installed_posix_stream(process: &Owned, stream: u32) -> Vec<u8> {
    let mut bytes = vec![0u8; 65536];
    let mut size = 0;
    assert_eq!(
        rax_process_output_read(
            process.0,
            stream,
            bytes.as_mut_ptr(),
            bytes.len(),
            &mut size
        ),
        RaxStatus::Ok
    );
    bytes.truncate(size);
    bytes
}

#[cfg(windows)]
#[test]
#[ignore = "run explicitly in the native Windows installed-process workflow"]
fn installed_cmd_ver_matches_native_through_closed_c_abi() {
    let native = compare_windows_installed_program("cmd.exe", &["/d", "/c", "ver"], None);
    assert!(native.status.success());
    assert!(!native.stdout.is_empty());

    let native = compare_windows_installed_command(
        "System32",
        "cmd.exe",
        &[],
        None,
        Some(r#"/d /c echo "rax-witness""#),
    );
    assert!(native.status.success());
    assert_eq!(native.stdout, b"\"rax-witness\"\r\n");
    assert!(native.stderr.is_empty());
}

#[cfg(all(windows, target_pointer_width = "64"))]
#[test]
#[ignore = "run explicitly in the native Windows installed-process workflow"]
fn installed_wow64_cmd_ver_matches_native_through_closed_c_abi() {
    trace_windows_installed_ntstatus();
    let native =
        compare_windows_installed_program_in("SysWOW64", "cmd.exe", &["/d", "/c", "ver"], None);
    assert!(native.status.success());
    assert!(!native.stdout.is_empty());
    assert!(native.stderr.is_empty());
}

#[cfg(windows)]
#[test]
#[ignore = "run explicitly in the native Windows installed-process workflow"]
fn installed_cmd_null_device_matches_native_through_closed_c_abi() {
    compare_installed_cmd_null_device("System32");
}

#[cfg(all(windows, target_pointer_width = "64"))]
#[test]
#[ignore = "run explicitly in the native Windows installed-process workflow"]
fn installed_wow64_cmd_null_device_matches_native_through_closed_c_abi() {
    trace_windows_installed_ntstatus();
    compare_installed_cmd_null_device("SysWOW64");
}

#[cfg(windows)]
fn compare_installed_cmd_null_device(directory: &str) {
    for arguments in [
        ["/d", "/c", "type", "NUL"],
        ["/d", "/c", "echo", "discarded>NUL"],
    ] {
        let native = compare_windows_installed_program_in(directory, "cmd.exe", &arguments, None);
        assert!(native.status.success(), "{arguments:?}");
        assert!(native.stdout.is_empty(), "{arguments:?}");
        assert!(native.stderr.is_empty(), "{arguments:?}");
    }
}

#[cfg(windows)]
#[test]
#[ignore = "run explicitly in the native Windows installed-process workflow"]
fn installed_cmd_child_matches_native_through_closed_c_abi() {
    trace_windows_installed_ntstatus();
    let system_cmd = std::path::PathBuf::from(std::env::var_os("SystemRoot").unwrap())
        .join("System32")
        .join("cmd.exe");
    let mut failures = Vec::new();
    for (label, args, exit_code, stdout) in [
        (
            "absolute child image",
            &[
                "/d",
                "/c",
                system_cmd.to_str().unwrap(),
                "/d",
                "/c",
                "echo",
                "rax-child",
            ][..],
            0,
            &b"rax-child\r\n"[..],
        ),
        (
            "child image basename",
            &["/d", "/c", "cmd.exe", "/d", "/c", "echo", "rax-child"][..],
            0,
            &b"rax-child\r\n"[..],
        ),
        (
            "child exit status",
            &["/d", "/c", "cmd.exe", "/d", "/c", "exit", "/b", "23"][..],
            23,
            &b""[..],
        ),
    ] {
        let result = std::panic::catch_unwind(|| {
            let native = compare_windows_installed_program("cmd.exe", args, None);
            assert_eq!(native.status.code(), Some(exit_code), "{label}");
            assert_eq!(native.stdout, stdout, "{label}");
            assert!(native.stderr.is_empty(), "{label}");
        });
        if result.is_err() {
            failures.push(label);
        }
    }
    assert!(
        failures.is_empty(),
        "installed child cases failed: {failures:?}"
    );
}

#[cfg(windows)]
#[test]
#[ignore = "run explicitly in the native Windows installed-process workflow"]
fn installed_findstr_matches_native_through_closed_c_abi() {
    check_native_extension_point_policy();
    let arguments = &["/l", "/c:rax-witness"];
    let matched = compare_windows_installed_program(
        "findstr.exe",
        arguments,
        Some(b"ignored\r\nrax-witness\r\n"),
    );
    assert_eq!(matched.status.code(), Some(0));
    assert_eq!(matched.stdout, b"rax-witness\r\n");
    assert!(matched.stderr.is_empty());

    let unmatched =
        compare_windows_installed_program("findstr.exe", arguments, Some(b"ignored\r\n"));
    assert_eq!(unmatched.status.code(), Some(1));
    assert!(unmatched.stdout.is_empty());
    assert!(unmatched.stderr.is_empty());
    compare_installed_sort();
}

#[cfg(windows)]
fn compare_installed_sort() {
    #[cfg(target_arch = "x86_64")]
    check_native_sort_process_queries();

    let mut failed = Vec::new();
    for (label, arguments) in [("default locale", &[][..]), ("C locale", &["/l", "C"][..])] {
        let matched = std::panic::catch_unwind(|| {
            let native = compare_windows_installed_program(
                "sort.exe",
                arguments,
                Some(b"delta\r\nalpha\r\ncharlie\r\n"),
            );
            assert_eq!(native.status.code(), Some(0));
            assert_eq!(native.stdout, b"alpha\r\ncharlie\r\ndelta\r\n");
            assert!(native.stderr.is_empty());
        });
        if matched.is_ok() {
            eprintln!("installed sort.exe {label}: matched native stdout, stderr and status");
        } else {
            failed.push(label);
        }
    }
    assert!(failed.is_empty(), "installed sort.exe failed: {failed:?}");
}

#[cfg(all(windows, target_arch = "x86_64"))]
fn check_native_sort_process_queries() {
    use std::ffi::c_void;

    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtQueryInformationProcess(
            process: *mut c_void,
            class: u32,
            output: *mut c_void,
            bytes: u32,
            returned: *mut u32,
        ) -> i32;
    }

    for (class, lengths) in [(1, &[48, 88][..]), (3, &[88, 96, 112][..])] {
        for &length in lengths {
            let mut output = [0u64; 14];
            let mut returned = u32::MAX;
            // SAFETY: This is a read-only query of the test's own process.
            // The 112-byte initialized output covers each requested size.
            let status = unsafe {
                NtQueryInformationProcess(
                    -1isize as *mut c_void,
                    class,
                    output.as_mut_ptr().cast(),
                    length,
                    &mut returned,
                )
            };
            eprintln!(
                "native current-process query: class={class} requested={length} status={status:#010x} returned={returned}"
            );
            assert_eq!((status, returned), (0, length), "class {class}");
        }
    }
}

#[cfg(windows)]
fn check_native_extension_point_policy() {
    use std::ffi::c_void;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetCurrentProcess() -> *mut c_void;
        fn GetProcessMitigationPolicy(
            process: *mut c_void,
            selector: u32,
            output: *mut c_void,
            length: usize,
        ) -> i32;
    }

    let mut flags = u32::MAX;
    let ok = unsafe {
        GetProcessMitigationPolicy(
            GetCurrentProcess(),
            6,
            (&raw mut flags).cast(),
            std::mem::size_of::<u32>(),
        )
    };
    assert_ne!(ok, 0, "{}", std::io::Error::last_os_error());
    assert_eq!(flags, 0, "installed process extension-point policy");
    eprintln!("native extension-point policy: flags=0x{flags:x}");
}

#[cfg(windows)]
fn trace_windows_installed_ntstatus() {
    if std::env::var("RAX_TEST_WINDOWS_NTSTATUS").as_deref() == Ok("true") {
        tracing_subscriber::fmt()
            .with_env_filter("rax::windows::ntstatus=trace")
            .without_time()
            .with_ansi(false)
            .try_init()
            .expect("install guest NT service status trace");
    }
}

#[cfg(windows)]
fn compare_windows_installed_program(
    image: &str,
    arguments: &[&str],
    stdin: Option<&[u8]>,
) -> std::process::Output {
    compare_windows_installed_program_in("System32", image, arguments, stdin)
}

#[cfg(windows)]
fn compare_windows_installed_program_in(
    directory_name: &str,
    image: &str,
    arguments: &[&str],
    stdin: Option<&[u8]>,
) -> std::process::Output {
    compare_windows_installed_command(directory_name, image, arguments, stdin, None)
}

#[cfg(windows)]
fn compare_windows_installed_command(
    directory_name: &str,
    image: &str,
    arguments: &[&str],
    stdin: Option<&[u8]>,
    raw_tail: Option<&str>,
) -> std::process::Output {
    use std::io::Write as _;
    use std::os::windows::process::CommandExt as _;
    use std::path::PathBuf;
    use std::process::{Command, Stdio};

    let system_root = PathBuf::from(std::env::var_os("SystemRoot").expect("Windows system root"));
    let system_directory = system_root.join(directory_name);
    let current_directory = system_directory
        .to_str()
        .expect("Unicode system library path");
    let program = system_directory.join(image);
    let program_path = program.to_str().expect("Unicode system program path");
    let command_interpreter = system_directory.join("cmd.exe");
    let environment = [
        (
            "SystemRoot",
            system_root.to_str().expect("Unicode system root"),
        ),
        ("windir", system_root.to_str().expect("Unicode system root")),
        (
            "ComSpec",
            command_interpreter.to_str().expect("Unicode cmd path"),
        ),
        ("PATH", current_directory),
    ];
    let mut command = Command::new(&program);
    if let Some(raw_tail) = raw_tail {
        command.raw_arg(raw_tail);
    } else {
        command.args(arguments);
    }
    command
        .current_dir(&system_directory)
        .env_clear()
        .envs(environment);
    let native = if let Some(input) = stdin {
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start native installed program");
        let mut pipe = child.stdin.take().expect("native standard input");
        pipe.write_all(input).expect("write native standard input");
        drop(pipe);
        child.wait_with_output().expect("native installed output")
    } else {
        command.output().expect("native installed output")
    };

    let bytes = std::fs::read(&program).expect("installed Windows executable");
    let mut options = serde_json::json!({
        "personality": "windows",
        "native_runtime": true,
        "guest_path": program_path,
        "current_directory": current_directory,
        "environment": environment.into_iter().collect::<std::collections::BTreeMap<_, _>>(),
        "memory_bytes": 268435456,
        "slice_instructions": 4096,
    });
    if let Some(raw_tail) = raw_tail {
        options["command_line"] = format!("\"{program_path}\" {raw_tail}").into();
    } else {
        options["arguments"] = serde_json::json!(arguments);
    }
    let process = open(&bytes, &options.to_string());
    if let Some(input) = stdin {
        assert_eq!(
            rax_process_stdin_feed(process.0, input.as_ptr(), input.len()),
            RaxStatus::Ok,
            "{}",
            error()
        );
    }
    let opened = info(&process);
    assert_eq!(opened["capabilities"]["native_runtime"], true);
    assert_eq!(opened["capabilities"]["host_filesystem"], false);
    if directory_name == "SysWOW64" {
        assert_eq!(opened["architecture"], "x86");
    }
    let modules = opened["modules"].as_array().expect("opened guest modules");
    assert!(
        modules.iter().any(|module| {
            module["name"] == "ntdll.dll"
                && module["path"]
                    .as_str()
                    .and_then(|path| path.rsplit(['\\', '/']).nth(1))
                    .is_some_and(|parent| parent.eq_ignore_ascii_case(directory_name))
        }),
        "no installed {directory_name} NTDLL in {modules:?}"
    );

    let mut result = RaxProcessResult::default();
    const MAX_TURNS: u64 = 16_384;
    let mut remaining = MAX_TURNS;
    loop {
        assert_ne!(
            remaining, 0,
            "{program_path}: guest exceeded {MAX_TURNS} turns"
        );
        let turns = remaining.min(256);
        assert_eq!(
            rax_process_run(process.0, turns, 0, &mut result),
            RaxStatus::Ok,
            "{}",
            error()
        );
        assert!(result.turns_started <= turns);
        remaining -= result.turns_started;
        if result.reason != RAX_PROCESS_BUDGET {
            break;
        }
        assert_ne!(result.turns_started, 0);
    }
    if result.reason != RAX_PROCESS_EXITED {
        eprintln!(
            "{program_path}: native exit status {:?}, stdout {} bytes, stderr {} bytes",
            native.status.code(),
            native.stdout.len(),
            native.stderr.len()
        );
        let stopped = info(&process);
        if let Some((service, name)) = stopped_native_request(&process, &stopped) {
            eprintln!("guest {service} requested {name:?}");
        }
        if let Some(shape) = stopped_token_duplicate_shape(&process, &stopped) {
            eprintln!("guest NtDuplicateToken request {shape}");
        }
        panic!(
            "guest {} stopped after {} scheduler turns: {}",
            opened["architecture"],
            MAX_TURNS - remaining,
            stopped["diagnostic"]
        );
    }
    let [stdout, stderr] = [RAX_PROCESS_STDOUT, RAX_PROCESS_STDERR].map(|stream| {
        let mut bytes = vec![0; 65536];
        let mut size = 0;
        assert_eq!(
            rax_process_output_read(
                process.0,
                stream,
                bytes.as_mut_ptr(),
                bytes.len(),
                &mut size
            ),
            RaxStatus::Ok
        );
        bytes.truncate(size);
        bytes
    });
    assert!(
        Some(result.exit_code) == native.status.code().map(i32::cast_unsigned)
            && stdout == native.stdout
            && stderr == native.stderr,
        "{program_path} {arguments:?}: guest status {}, stdout {:?}, stderr {:?}; \
        native status {:?}, stdout {:?}, stderr {:?}",
        result.exit_code,
        String::from_utf8_lossy(&stdout),
        String::from_utf8_lossy(&stderr),
        native.status.code(),
        String::from_utf8_lossy(&native.stdout),
        String::from_utf8_lossy(&native.stderr)
    );
    native
}

#[cfg(windows)]
fn stopped_token_duplicate_shape(process: &Owned, stopped: &serde_json::Value) -> Option<String> {
    let diagnostic = stopped["diagnostic"].as_str()?;
    let suffix =
        diagnostic.strip_prefix("emulator failure: native NTDLL service NtDuplicateToken")?;
    if !suffix.starts_with([':', ' ']) {
        return None;
    }
    let thread = ready_native_thread(stopped)?;
    let hex = |value: &serde_json::Value| {
        u64::from_str_radix(value.as_str()?.strip_prefix("0x")?, 16).ok()
    };
    let register = |index| hex(thread["registers"].get(index)?);
    let read = |address, bytes: &mut [u8]| {
        rax_process_mem_read(process.0, address, bytes.as_mut_ptr(), bytes.len()) == RaxStatus::Ok
    };
    let (source, access, attributes, effective, kind, output) =
        match stopped["architecture"].as_str()? {
            "x64" => {
                let sp = hex(&thread["sp"])?;
                let mut stack = [0; 16];
                if !read(sp.checked_add(40)?, &mut stack) {
                    return None;
                }
                (
                    register(10usize)?,
                    register(2)?,
                    register(8)?,
                    register(9)?,
                    u64::from_le_bytes(stack[..8].try_into().ok()?),
                    u64::from_le_bytes(stack[8..].try_into().ok()?),
                )
            }
            "arm64" => (
                register(0)?,
                register(1)?,
                register(2)?,
                register(3)?,
                register(4)?,
                register(5)?,
            ),
            _ => return None,
        };
    let role = match source {
        0 => "null",
        u64::MAX => "current-process",
        n if n == u64::MAX - 1 => "current-thread",
        n if n == u64::MAX - 3 => "current-process-token",
        n if n == u64::MAX - 4 => "current-thread-token",
        n if n == u64::MAX - 5 => "current-thread-effective-token",
        _ => "handle",
    };
    let mut shape = format!(
        "source={role} access={:#x} effective={} kind={} output_present={}",
        access as u32,
        effective as u8,
        kind as u32,
        output != 0
    );
    if attributes == 0 {
        shape.push_str(" attributes=absent");
        return Some(shape);
    }
    let mut header = [0; 48];
    if !read(attributes, &mut header) {
        shape.push_str(" attributes=unreadable");
        return Some(shape);
    }
    let word = |offset| u32::from_le_bytes(header[offset..offset + 4].try_into().unwrap());
    let pointer = |offset| u64::from_le_bytes(header[offset..offset + 8].try_into().unwrap());
    let quality = pointer(40);
    shape.push_str(&format!(
        " attributes_bytes={} flags={:#x} named={} descriptor_present={}",
        word(0),
        word(24),
        pointer(8) != 0 || pointer(16) != 0,
        pointer(32) != 0
    ));
    if quality == 0 {
        shape.push_str(" quality=absent");
    } else {
        let mut qos = [0; 12];
        if read(quality, &mut qos) {
            let length = u32::from_le_bytes(qos[..4].try_into().ok()?);
            let level = u32::from_le_bytes(qos[4..8].try_into().ok()?);
            shape.push_str(&format!(
                " quality_bytes={length} level={level} tracking={} quality_effective={}",
                qos[8], qos[9]
            ));
        } else {
            shape.push_str(" quality=unreadable");
        }
    }
    Some(shape)
}

#[cfg(windows)]
fn ready_native_thread(stopped: &serde_json::Value) -> Option<&serde_json::Value> {
    let mut ready = stopped["threads"]
        .as_array()?
        .iter()
        .filter(|thread| thread["state"] == "ready");
    let thread = ready.next()?;
    ready.next().is_none().then_some(thread)
}

#[cfg(windows)]
fn stopped_native_request(
    process: &Owned,
    stopped: &serde_json::Value,
) -> Option<(&'static str, String)> {
    let diagnostic = stopped["diagnostic"].as_str()?;
    let (service, argument) = match diagnostic
        .strip_prefix("emulator failure: native NTDLL service ")?
        .split_once(": ")?
        .0
    {
        "NtOpenKey" if diagnostic.contains("registry key outside selected runtime snapshot") => {
            ("NtOpenKey", 2)
        }
        "NtOpenFile"
            if diagnostic.contains("NT metadata name outside mapped DOS drive namespace") =>
        {
            ("NtOpenFile", 2)
        }
        "NtQueryLicenseValue" if diagnostic.contains("unmeasured NtQueryLicenseValue profile") => {
            ("NtQueryLicenseValue", 0)
        }
        "NtConnectPort" if diagnostic.contains("requires a matched selected guest server") => {
            ("NtConnectPort", 1)
        }
        _ => return None,
    };
    // At the native x64 syscall boundary, R10 holds the first argument.
    let register = match stopped["architecture"].as_str()? {
        "x64" => [10, 2, 8][argument],
        "arm64" => argument,
        _ => return None,
    };
    let thread = ready_native_thread(stopped)?;
    let address = thread["registers"]
        .get(register)?
        .as_str()?
        .strip_prefix("0x")?;
    let mut descriptor = u64::from_str_radix(address, 16).ok()?;
    let read = |address, bytes: &mut [u8]| {
        rax_process_mem_read(process.0, address, bytes.as_mut_ptr(), bytes.len()) == RaxStatus::Ok
    };
    if matches!(service, "NtOpenKey" | "NtOpenFile") {
        // These stops are expected for absolute names. Resolve the native64
        // OBJECT_ATTRIBUTES.ObjectName only when RootDirectory is null.
        let mut attributes = [0; 48];
        if !read(descriptor, &mut attributes)
            || attributes[..4] != 48_u32.to_le_bytes()
            || attributes[8..16] != [0; 8]
        {
            return None;
        }
        descriptor = u64::from_le_bytes(attributes[16..24].try_into().ok()?);
    }
    let mut header = [0; 16];
    if !read(descriptor, &mut header) {
        return None;
    }
    let length = usize::from(u16::from_le_bytes([header[0], header[1]]));
    let maximum = usize::from(u16::from_le_bytes([header[2], header[3]]));
    let buffer = u64::from_le_bytes(header[8..].try_into().ok()?);
    let mut storage = [0; 512];
    let bytes = storage.get_mut(..length)?;
    if length == 0 || length % 2 != 0 || length > maximum || !read(buffer, bytes) {
        return None;
    }
    let units: Vec<_> = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    Some((service, String::from_utf16(&units).ok()?))
}

#[cfg(windows)]
#[test]
fn installed_ntdll_is_selected_and_its_termination_leaf_runs_through_c_abi() {
    use rax_engine::user::image::pe::exports::{ExportDirectory, ExportTarget};
    use rax_engine::user::image::pe::{DataDirectory, RvaFault, RvaSource, dir};
    use rax_engine::user::windows::{dll, loader::builtin};
    let arch = if cfg!(target_arch = "aarch64") {
        WinArch::Arm64
    } else if cfg!(target_arch = "x86_64") {
        WinArch::X64
    } else {
        WinArch::X86
    };
    let base = if arch.is64() { 0x140000000 } else { 0x400000 };
    let mut image = builtin::build(dll::find("ntdll.dll").unwrap(), arch, base, &[]).bytes;
    let pe = u32::from_le_bytes(image[0x3c..0x40].try_into().unwrap()) as usize;
    let flags = u16::from_le_bytes(image[pe + 22..pe + 24].try_into().unwrap()) & !0x2000;
    image[pe + 22..pe + 24].copy_from_slice(&flags.to_le_bytes());
    image[pe + 24 + 68..pe + 24 + 70].copy_from_slice(&1u16.to_le_bytes());
    let options =
        r#"{"native_runtime":true,"guest_path":"C:\\app\\probe.exe","memory_bytes":268435456}"#;
    let process = open(&image, options);
    let before = info(&process);
    assert_eq!(before["capabilities"]["native_runtime"], true);
    assert_eq!(before["capabilities"]["host_filesystem"], false);
    let ntdll = before["modules"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["name"] == "ntdll.dll")
        .unwrap();
    assert!(
        ntdll["path"]
            .as_str()
            .unwrap()
            .to_ascii_lowercase()
            .contains("system32")
    );
    struct Guest<'a> {
        process: &'a Owned,
        base: u64,
    }
    impl RvaSource for Guest<'_> {
        fn read_rva(&self, rva: u64, bytes: &mut [u8]) -> Result<(), RvaFault> {
            let address = self.base.checked_add(rva).ok_or(RvaFault { rva })?;
            if rax_process_mem_read(self.process.0, address, bytes.as_mut_ptr(), bytes.len())
                == RaxStatus::Ok
            {
                Ok(())
            } else {
                Err(RvaFault { rva })
            }
        }
    }
    let guest = Guest {
        process: &process,
        base: address(&ntdll["base"]),
    };
    let pe = u64::from(guest.u32_at(0x3c).unwrap());
    let directories = pe + 24 + if arch.is64() { 112 } else { 96 };
    let at = directories + dir::EXPORT as u64 * 8;
    let range = DataDirectory {
        rva: guest.u32_at(at).unwrap(),
        size: guest.u32_at(at + 4).unwrap(),
    };
    let exports = ExportDirectory::read(&guest, range).unwrap().unwrap();
    let (_, ExportTarget::Rva(rva)) = exports
        .by_name(&guest, b"NtTerminateProcess", None)
        .unwrap()
        .unwrap()
    else {
        panic!("installed termination leaf is a forwarder");
    };
    let tid = before["threads"][0]["id"].as_u64().unwrap() as u32;
    let mut registers = RegContext::from_bytes(arch, context(&process, tid));
    registers.set_pc(guest.base + u64::from(rva));
    if arch == WinArch::X64 {
        registers.set_gpr(1, u64::MAX);
        registers.set_gpr(2, 73);
    } else if arch == WinArch::Arm64 {
        registers.set_gpr(0, u64::MAX);
        registers.set_gpr(1, 73);
    } else {
        let arguments = [0u32, u32::MAX, 73]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<_>>();
        assert_eq!(
            rax_process_mem_write(
                process.0,
                registers.sp(),
                arguments.as_ptr(),
                arguments.len()
            ),
            RaxStatus::Ok
        );
    }
    assert_eq!(
        rax_process_context_write(
            process.0,
            tid,
            registers.bytes().as_ptr(),
            registers.bytes().len()
        ),
        RaxStatus::Ok
    );
    let mut result = RaxProcessResult::default();
    assert_eq!(
        rax_process_run(process.0, 16, 5_000_000, &mut result),
        RaxStatus::Ok
    );
    assert_eq!(result.reason, RAX_PROCESS_EXITED, "{}", info(&process));
    assert_eq!(result.exit_code, 73);

    let name = "C:\\app\\ntdll.dll";
    let broken = b"invalid supplied NTDLL";
    let supplied = RaxProcessImage {
        path: name.as_ptr().cast(),
        path_size: name.len(),
        data: broken.as_ptr(),
        data_size: broken.len(),
    };
    assert!(!refused(&image, options, &[supplied], RaxStatus::Format).is_empty());
}
