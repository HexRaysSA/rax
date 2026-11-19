//! Fixed primary-subject input for the local Policy Lookup compatibility profile.

#[derive(Clone)]
pub(crate) struct Name {
    pub(crate) units: Vec<u16>,
    pub(crate) maximum_units: u16,
}

pub(crate) struct PrimaryAccount {
    pub(crate) user_sid: Vec<u8>,
    pub(crate) domain_sid: Vec<u8>,
    pub(crate) domain: Name,
    pub(crate) account: Name,
}

impl std::fmt::Debug for PrimaryAccount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrimaryAccount").finish_non_exhaustive()
    }
}

#[cfg(windows)]
mod installed {
    use super::{Name, PrimaryAccount};
    use crate::user::windows::security;
    use std::ffi::c_void;
    use std::ptr::{null, null_mut};

    const POLICY_LOOKUP_NAMES: u32 = 0x0800;
    const SID_TYPE_USER: u32 = 1;
    const MAX_NAME_BYTES: u16 = 1024;

    #[repr(C)]
    struct Unicode {
        length: u16,
        maximum: u16,
        buffer: *const u16,
    }

    #[repr(C)]
    struct ObjectAttributes {
        length: u32,
        root: *mut c_void,
        name: *const Unicode,
        flags: u32,
        security: *const c_void,
        qos: *const c_void,
    }

    #[repr(C)]
    struct Domain {
        name: Unicode,
        sid: *const u8,
    }

    #[repr(C)]
    struct Domains {
        count: u32,
        entries: *const Domain,
    }

    #[repr(C)]
    struct TranslatedName {
        kind: u32,
        name: Unicode,
        domain_index: i32,
    }

    type Handle = *mut c_void;

    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn LsaOpenPolicy(
            system: *const Unicode,
            attributes: *const ObjectAttributes,
            access: u32,
            policy: *mut Handle,
        ) -> i32;
        fn LsaLookupSids2(
            policy: Handle,
            options: u32,
            count: u32,
            sids: *const *const u8,
            domains: *mut *mut Domains,
            names: *mut *mut TranslatedName,
        ) -> i32;
        fn LsaClose(policy: Handle) -> i32;
        fn LsaFreeMemory(memory: *mut c_void) -> i32;
    }

    struct Policy(Handle);
    impl Drop for Policy {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: the only owner of the handle returned by LsaOpenPolicy.
                unsafe { LsaClose(self.0) };
            }
        }
    }

    struct Allocation<T>(*mut T);
    impl<T> Drop for Allocation<T> {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: this allocation was returned by LsaLookupSids2.
                unsafe { LsaFreeMemory(self.0.cast()) };
            }
        }
    }

    // The counted buffer is borrowed only while its owning LSA allocation lives.
    fn copy_name(value: &Unicode) -> Option<Name> {
        if value.length == 0
            || value.length > value.maximum
            || value.maximum > MAX_NAME_BYTES
            || value.length % 2 != 0
            || value.maximum % 2 != 0
            || value.buffer.is_null()
        {
            return None;
        }
        // SAFETY: a successful native lookup supplies a live WCHAR buffer of
        // the reported byte length. The enclosing allocation is still owned.
        let units =
            unsafe { std::slice::from_raw_parts(value.buffer, usize::from(value.length / 2)) };
        if units.contains(&0) {
            return None;
        }
        Some(Name {
            units: units.to_vec(),
            maximum_units: value.maximum / 2,
        })
    }

    /// Look up the selected process primary subject once during host selection.
    /// No guest request can supply a SID or a system name to this API.
    pub(super) fn capture(user_sid: &[u8]) -> Option<PrimaryAccount> {
        if security::sid(user_sid)? != user_sid {
            return None;
        }
        // A Windows SID contains at most 15 DWORD subauthorities after its
        // eight-byte header. Preserve DWORD alignment for the native input.
        let mut input = [0u32; 17];
        let sid = input.as_mut_ptr().cast::<u8>();
        // SAFETY: the SID length was bounded above and input is disjoint.
        unsafe { std::ptr::copy_nonoverlapping(user_sid.as_ptr(), sid, user_sid.len()) };
        let sid = sid.cast_const();
        let attributes = ObjectAttributes {
            length: std::mem::size_of::<ObjectAttributes>() as u32,
            root: null_mut(),
            name: null(),
            flags: 0,
            security: null(),
            qos: null(),
        };
        let mut policy = Policy(null_mut());
        // SAFETY: local policy and exclusive output storage with the documented layout.
        if unsafe { LsaOpenPolicy(null(), &attributes, POLICY_LOOKUP_NAMES, &mut policy.0) } != 0
            || policy.0.is_null()
        {
            return None;
        }
        let mut domains = Allocation::<Domains>(null_mut());
        let mut names = Allocation::<TranslatedName>(null_mut());
        // SAFETY: one live input SID and independent outputs scoped to this call.
        if unsafe { LsaLookupSids2(policy.0, 0, 1, &sid, &mut domains.0, &mut names.0) } != 0 {
            return None;
        }
        // SAFETY: successful lookup returns one translated record per input SID.
        let name = unsafe { names.0.as_ref() }?;
        // SAFETY: the returned domain list remains owned by domains.
        let referenced = unsafe { domains.0.as_ref() }?;
        if name.kind != SID_TYPE_USER || name.domain_index != 0 || referenced.count != 1 {
            return None;
        }
        // SAFETY: the successful one-entry list owns its first entry and its SID.
        let domain = unsafe { referenced.entries.as_ref() }?;
        if domain.sid.is_null() {
            return None;
        }
        // SAFETY: the native domain SID has its fixed header and count-declared
        // length within the live LSA allocation.
        let count = unsafe { *domain.sid.add(1) };
        if count > 15 {
            return None;
        }
        let sid = unsafe { std::slice::from_raw_parts(domain.sid, 8 + 4 * usize::from(count)) };
        Some(PrimaryAccount {
            user_sid: user_sid.to_vec(),
            domain_sid: security::sid(sid)?.to_vec(),
            domain: copy_name(&domain.name)?,
            account: copy_name(&name.name)?,
        })
    }
}

pub(crate) fn capture(user_sid: &[u8]) -> Option<PrimaryAccount> {
    #[cfg(windows)]
    {
        installed::capture(user_sid)
    }
    #[cfg(not(windows))]
    {
        let _ = user_sid;
        None
    }
}
