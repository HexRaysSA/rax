//! Captured account names for the local Policy Lookup compatibility profile.

use crate::user::windows::security::Subject;
use std::collections::BTreeMap;

pub(crate) struct Name {
    pub(crate) units: Vec<u16>,
    pub(crate) maximum_units: u16,
}

/// Domain policy for the measured standalone-machine profile.
pub(crate) struct StandalonePolicy {
    pub(crate) dns_name: Name,
    pub(crate) account_domain: Option<AccountDomain>,
}

pub(crate) struct AccountDomain {
    pub(crate) name: Name,
    pub(crate) sid: Vec<u8>,
}

impl std::fmt::Debug for StandalonePolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StandalonePolicy").finish_non_exhaustive()
    }
}

pub(crate) struct Translation {
    pub(crate) kind: u32,
    pub(crate) domain_sid: Vec<u8>,
    pub(crate) domain: Name,
    pub(crate) account: Name,
}

pub(crate) struct Catalog {
    pub(crate) primary_sid: Vec<u8>,
    pub(crate) entries: BTreeMap<Vec<u8>, Translation>,
}

impl Catalog {
    pub(crate) fn translate(&self, subject: &Subject, sid: &[u8]) -> Option<&Translation> {
        if self.primary_sid != subject.user {
            return None;
        }
        let translation = self.entries.get(sid)?;
        (sid == subject.user || subject.groups.iter().any(|group| group.sid == sid))
            .then_some(translation)
    }
}

impl std::fmt::Debug for Catalog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Catalog").finish_non_exhaustive()
    }
}

#[cfg(windows)]
mod installed {
    use super::{AccountDomain, BTreeMap, Catalog, Name, StandalonePolicy, Subject, Translation};
    use crate::user::windows::security;
    use std::ffi::c_void;
    use std::ptr::{null, null_mut};

    const POLICY_LOOKUP_NAMES: u32 = 0x0800;
    const POLICY_VIEW_LOCAL_INFORMATION: u32 = 0x0001;
    const POLICY_ACCOUNT_DOMAIN_INFORMATION: u32 = 5;
    const POLICY_DNS_DOMAIN_INFORMATION: u32 = 12;
    const STATUS_SOME_NOT_MAPPED: i32 = 0x107;
    const SID_TYPE_USER: u32 = 1;
    const SID_TYPE_GROUP: u32 = 2;
    const SID_TYPE_ALIAS: u32 = 4;
    const SID_TYPE_WELL_KNOWN_GROUP: u32 = 5;
    const SID_TYPE_LABEL: u32 = 10;
    const MAX_NAME_BYTES: u16 = 1024;
    // The SID fixed header and its maximum of 15 four-byte subauthorities.
    const MAX_SID_WORDS: usize = 17;

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
    struct DnsDomainInformation {
        name: Unicode,
        dns_domain: Unicode,
        dns_forest: Unicode,
        guid: [u32; 4],
        sid: *const u8,
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
        fn LsaQueryInformationPolicy(policy: Handle, class: u32, buffer: *mut *mut c_void) -> i32;
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
                // SAFETY: this allocation was returned by LSA with ownership.
                unsafe { LsaFreeMemory(self.0.cast()) };
            }
        }
    }

    // The counted buffer is borrowed only while its owning LSA allocation lives.
    fn copy_name(value: &Unicode) -> Option<Name> {
        if value.maximum == 0
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

    fn copy_sid(sid: *const u8) -> Option<Vec<u8>> {
        if sid.is_null() {
            return None;
        }
        // SAFETY: the native domain SID has its fixed header and count-declared
        // length within the live LSA allocation.
        let count = unsafe { *sid.add(1) };
        if count > 15 {
            return None;
        }
        // SAFETY: the native allocation owns the previously bounded SID.
        let sid = unsafe { std::slice::from_raw_parts(sid, 8 + 4 * usize::from(count)) };
        Some(security::sid(sid)?.to_vec())
    }

    fn copy_translation(name: &TranslatedName, domain: &Domain) -> Option<Translation> {
        let domain_sid = copy_sid(domain.sid)?;
        let account = copy_name(&name.name)?;
        if account.units.is_empty() {
            return None;
        }
        Some(Translation {
            kind: name.kind,
            domain_sid,
            domain: copy_name(&domain.name)?,
            account,
        })
    }

    fn add_translations(
        policy: &Policy,
        sids: &[&[u8]],
        accepts: impl Fn(u32) -> bool,
        entries: &mut BTreeMap<Vec<u8>, Translation>,
    ) {
        if sids.is_empty() {
            return;
        }
        // Use DWORD-aligned native storage for the already validated SID bytes.
        let mut inputs = vec![[0u32; MAX_SID_WORDS]; sids.len()];
        for (input, sid) in inputs.iter_mut().zip(sids) {
            // SAFETY: every input SID fits and has storage disjoint from inputs.
            unsafe {
                std::ptr::copy_nonoverlapping(sid.as_ptr(), input.as_mut_ptr().cast(), sid.len())
            };
        }
        let pointers: Vec<_> = inputs.iter().map(|input| input.as_ptr().cast()).collect();
        let mut domains = Allocation::<Domains>(null_mut());
        let mut names = Allocation::<TranslatedName>(null_mut());
        // SAFETY: input pointers name live, aligned SIDs and the outputs are exclusive.
        let status = unsafe {
            LsaLookupSids2(
                policy.0,
                0,
                pointers.len() as u32,
                pointers.as_ptr(),
                &mut domains.0,
                &mut names.0,
            )
        };
        if !matches!(status, 0 | STATUS_SOME_NOT_MAPPED) || names.0.is_null() {
            return;
        }
        // SAFETY: the returned domain list remains owned by domains.
        let Some(referenced) = (unsafe { domains.0.as_ref() }) else {
            return;
        };
        if referenced.count as usize > sids.len() || referenced.entries.is_null() {
            return;
        }
        // SAFETY: LSA returns one name per input and a counted domain array.
        let translated = unsafe { std::slice::from_raw_parts(names.0, sids.len()) };
        let referenced =
            unsafe { std::slice::from_raw_parts(referenced.entries, referenced.count as usize) };
        for (&sid, name) in sids.iter().zip(translated) {
            if !accepts(name.kind) {
                continue;
            }
            let Ok(index) = usize::try_from(name.domain_index) else {
                continue;
            };
            if let Some(translation) = referenced
                .get(index)
                .and_then(|domain| copy_translation(name, domain))
            {
                entries.entry(sid.to_vec()).or_insert(translation);
            }
        }
    }

    fn open_policy(access: u32) -> Option<Policy> {
        let attributes = ObjectAttributes {
            length: std::mem::size_of::<ObjectAttributes>() as u32,
            root: null_mut(),
            name: null(),
            flags: 0,
            security: null(),
            qos: null(),
        };
        let mut policy = Policy(null_mut());
        // SAFETY: this opens the local query policy into exclusive output storage.
        if unsafe { LsaOpenPolicy(null(), &attributes, access, &mut policy.0) } != 0
            || policy.0.is_null()
        {
            return None;
        }
        Some(policy)
    }

    /// Resolve only the selected host token during runtime selection.
    pub(super) fn capture(subject: &Subject) -> Option<Catalog> {
        let user = subject.user.as_slice();
        if security::sid(user)? != user {
            return None;
        }
        let policy = open_policy(POLICY_LOOKUP_NAMES)?;
        let mut entries = BTreeMap::new();
        // Mixed batches can change the primary user's counted name metadata.
        add_translations(&policy, &[user], |kind| kind == SID_TYPE_USER, &mut entries);
        let groups: Vec<_> = subject
            .groups
            .iter()
            .map(|group| group.sid.as_slice())
            .filter(|&sid| security::sid(sid) == Some(sid))
            .collect();
        add_translations(
            &policy,
            &groups,
            |kind| {
                matches!(
                    kind,
                    SID_TYPE_GROUP | SID_TYPE_ALIAS | SID_TYPE_WELL_KNOWN_GROUP | SID_TYPE_LABEL
                )
            },
            &mut entries,
        );
        (!entries.is_empty()).then(|| Catalog {
            primary_sid: user.to_vec(),
            entries,
        })
    }

    fn query_policy(policy: &Policy, class: u32) -> Option<Allocation<c_void>> {
        let mut result = Allocation::<c_void>(null_mut());
        // SAFETY: this fixed local query uses a live policy and an exclusive output.
        let status = unsafe { LsaQueryInformationPolicy(policy.0, class, &mut result.0) };
        (status == 0).then_some(result)
    }

    fn account_domain(policy: &Policy) -> Option<AccountDomain> {
        let allocation = query_policy(policy, POLICY_ACCOUNT_DOMAIN_INFORMATION)?;
        // SAFETY: the successful query owns a live POLICY_ACCOUNT_DOMAIN_INFO.
        let domain = unsafe { allocation.0.cast::<Domain>().as_ref() }?;
        Some(AccountDomain {
            name: copy_name(&domain.name)?,
            sid: copy_sid(domain.sid)?,
        })
    }

    pub(super) fn capture_domain_policy() -> Option<StandalonePolicy> {
        let policy = open_policy(POLICY_VIEW_LOCAL_INFORMATION)?;
        let allocation = query_policy(&policy, POLICY_DNS_DOMAIN_INFORMATION)?;
        // SAFETY: the successful query owns a live POLICY_DNS_DOMAIN_INFO.
        let result = unsafe { allocation.0.cast::<DnsDomainInformation>().as_ref() }?;
        let is_absent =
            |name: &Unicode| name.length == 0 && name.maximum == 0 && name.buffer.is_null();
        if !is_absent(&result.dns_domain)
            || !is_absent(&result.dns_forest)
            || result.guid != [0; 4]
            || !result.sid.is_null()
        {
            return None;
        }
        Some(StandalonePolicy {
            dns_name: copy_name(&result.name)?,
            account_domain: account_domain(&policy),
        })
    }
}

#[cfg(windows)]
pub(crate) fn capture_domain_policy() -> Option<StandalonePolicy> {
    installed::capture_domain_policy()
}

pub(crate) fn capture(subject: &Subject) -> Option<Catalog> {
    #[cfg(windows)]
    {
        installed::capture(subject)
    }
    #[cfg(not(windows))]
    {
        let _ = subject;
        None
    }
}
