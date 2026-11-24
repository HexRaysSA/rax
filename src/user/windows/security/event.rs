//! Immutable security for process-local unnamed events with the measured ACLs.
use super::Subject;
use super::token::pointer_records::Class;

pub(crate) const HEADER: [u8; 20] = [
    1, 0, 4, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 20, 0, 0, 0,
];
pub(crate) const MAX_ACL_SIZE: usize = 48;
const CREATOR_OWNER: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 3, 0, 0, 0, 0];
const AUTHENTICATED_USERS: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 5, 11, 0, 0, 0];
const CREATOR_GENERIC_ALL: u32 = 0x1000_0000;
const EVENT_ALL_ACCESS: u32 = 0x001f_0003;
const EVENT_MODIFY_STATE: u32 = 2;

pub(crate) struct EventSecurity {
    owner: Box<[u8]>,
    group: Box<[u8]>,
    dacl: Box<[u8]>,
}

impl std::fmt::Debug for EventSecurity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventSecurity").finish_non_exhaustive()
    }
}

impl EventSecurity {
    pub(crate) fn capture(subject: &Subject, acl: &[u8]) -> Option<Self> {
        if subject.app_container || !subject.restricted.is_empty() {
            return None;
        }
        let (used, creator) = match acl.get(..8)? {
            [2, 0, 48, 0, 2, 0, 0, 0] if acl.len() == 48 => (48, true),
            [2, 0, size, 0, 1, 0, 0, 0]
                if matches!(size, 28 | 48) && acl.len() == usize::from(*size) =>
            {
                (28, false)
            }
            _ => return None,
        };
        let sid_matches = |ace: &[u8], mask: u32, sid: &[u8; 12]| {
            ace[..4] == [0, 0, 20, 0] && ace[4..8] == mask.to_le_bytes() && ace[8..] == *sid
        };
        if creator && !sid_matches(&acl[8..28], CREATOR_GENERIC_ALL, &CREATOR_OWNER) {
            return None;
        }
        if !sid_matches(
            &acl[used - 20..used],
            EVENT_MODIFY_STATE,
            &AUTHENTICATED_USERS,
        ) {
            return None;
        }
        let default_sid = |class| {
            let bytes = subject.token_pointer_records.get(class)?;
            (super::sid(bytes)?.len() == bytes.len()).then(|| Box::from(bytes))
        };
        let mut dacl: Box<[u8]> = Box::from(&acl[..used]);
        dacl[2..4].copy_from_slice(&(used as u16).to_le_bytes());
        if creator {
            dacl[12..16].copy_from_slice(&EVENT_ALL_ACCESS.to_le_bytes());
        }
        Some(Self {
            owner: default_sid(Class::Owner)?,
            group: default_sid(Class::PrimaryGroup)?,
            dacl,
        })
    }

    pub(crate) fn descriptor(&self, mask: u32) -> Option<Vec<u8>> {
        // LABEL is accepted. This event profile has no explicit label or SACL.
        if mask & !0x17 != 0 {
            return None;
        }
        let mut descriptor = vec![0; HEADER.len()];
        descriptor[0] = 1;
        descriptor[2] = if mask & 4 != 0 { 4 } else { 0 };
        descriptor[3] = 0x80;
        for (bit, field, bytes) in [
            (1, 4, &*self.owner),
            (2, 8, &*self.group),
            (4, 16, &*self.dacl),
        ] {
            if mask & bit != 0 {
                let offset = descriptor.len() as u32;
                descriptor[field..field + 4].copy_from_slice(&offset.to_le_bytes());
                descriptor.extend_from_slice(bytes);
            }
        }
        Some(descriptor)
    }
}
