//! Native control using only the test process's own token.
use std::ffi::c_void;
use std::mem::size_of;
use std::ptr::{null, null_mut};

const TOKEN_DUPLICATE: u32 = 0x0002;
const TOKEN_IMPERSONATE: u32 = 0x0004;
const TOKEN_QUERY: u32 = 0x0008;
const TOKEN_IMPERSONATION: u32 = 2;
const SECURITY_IMPERSONATION: u32 = 2;
const STATUS_ACCESS_DENIED: u32 = 0xc000_0022;

type Handle = *mut c_void;

#[repr(C)]
struct QualityOfService {
    length: u32,
    level: u32,
    dynamic_tracking: u8,
    effective_only: u8,
}

#[repr(C)]
struct ObjectAttributes {
    length: u32,
    root: Handle,
    name: *const c_void,
    flags: u32,
    descriptor: *const c_void,
    quality: *const QualityOfService,
}

const _: [(); 12] = [(); size_of::<QualityOfService>()];
const _: [(); 48] = [(); size_of::<ObjectAttributes>()];

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetCurrentProcess() -> Handle;
    fn CloseHandle(handle: Handle) -> i32;
}

#[link(name = "advapi32")]
unsafe extern "system" {
    fn OpenProcessToken(process: Handle, desired: u32, output: *mut Handle) -> i32;
    fn GetTokenInformation(
        token: Handle,
        class: u32,
        value: *mut u32,
        length: u32,
        returned: *mut u32,
    ) -> i32;
}

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtDuplicateToken(
        source: Handle,
        desired: u32,
        attributes: *const ObjectAttributes,
        effective_only: u8,
        kind: u32,
        output: *mut Handle,
    ) -> i32;
}

struct Token(Handle);

impl Token {
    fn current(access: u32) -> Self {
        let mut token = Self(null_mut());
        // SAFETY: fixed current-process pseudo handle and owned output.
        assert_ne!(
            unsafe { OpenProcessToken(GetCurrentProcess(), access, &mut token.0) },
            0
        );
        assert!(!token.0.is_null());
        token
    }

    fn scalar_info(&self, class: u32) -> u32 {
        let mut value = 0;
        let mut returned = 0;
        // SAFETY: owned query handle and scalar output for TokenType or TokenImpersonationLevel.
        assert_ne!(
            unsafe { GetTokenInformation(self.0, class, &mut value, 4, &mut returned) },
            0
        );
        assert_eq!(returned, 4);
        value
    }
}

impl Drop for Token {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: this is an owned token handle returned by the OS.
            unsafe { CloseHandle(self.0) };
        }
    }
}

#[test]
#[ignore = "requires a native Windows AMD64 or ARM64 runner"]
fn installed_current_subject_duplicate_matches_guest_request() {
    let quality = QualityOfService {
        length: size_of::<QualityOfService>() as u32,
        level: SECURITY_IMPERSONATION,
        dynamic_tracking: 1,
        effective_only: 0,
    };
    let attributes = ObjectAttributes {
        length: size_of::<ObjectAttributes>() as u32,
        root: null_mut(),
        name: null(),
        flags: 0,
        descriptor: null(),
        quality: &quality,
    };
    let source = Token::current(TOKEN_QUERY | TOKEN_DUPLICATE);
    let query_only = Token::current(TOKEN_QUERY);
    let mut target = Token(null_mut());
    let mut denied = Token(null_mut());

    // SAFETY: own immutable primary token, live fixed-size inputs and exclusive output.
    // The test queries the new handle and closes it at scope exit.
    let success = unsafe {
        NtDuplicateToken(
            source.0,
            TOKEN_IMPERSONATE | TOKEN_QUERY,
            &attributes,
            0,
            TOKEN_IMPERSONATION,
            &mut target.0,
        )
    } as u32;
    let access_denied = unsafe {
        NtDuplicateToken(
            query_only.0,
            TOKEN_IMPERSONATE | TOKEN_QUERY,
            &attributes,
            0,
            TOKEN_IMPERSONATION,
            &mut denied.0,
        )
    } as u32;
    assert_eq!(success, 0);
    assert!(!target.0.is_null());
    assert_ne!(target.0, source.0);
    assert_eq!(target.scalar_info(8), TOKEN_IMPERSONATION);
    assert_eq!(target.scalar_info(9), SECURITY_IMPERSONATION);
    assert_eq!(source.scalar_info(8), 1);
    assert_eq!(access_denied, STATUS_ACCESS_DENIED);
    assert!(denied.0.is_null());
    eprintln!("native duplicate complete: access=0xc type=2 level=2 denied_query_only=1");
}
