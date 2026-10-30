//! Captured token subjects and bounded classic-DACL evaluation.
pub(crate) mod thread;
pub(crate) mod token;

use super::nt::status::{STATUS_ACCESS_DENIED, STATUS_PRIVILEGE_NOT_HELD};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Group {
    pub(crate) sid: Vec<u8>,
    pub(crate) attributes: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Privilege {
    pub(crate) luid: u64,
    pub(crate) attributes: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Subject {
    /// Fixed statistics captured from this exact token, never a host HANDLE.
    pub(crate) statistics: Option<token::statistics::Statistics>,
    /// Opaque TOKEN_USER SID attributes, captured without interpretation.
    pub(crate) user_attributes: u32,
    pub(crate) user: Vec<u8>,
    pub(crate) groups: Vec<Group>,
    pub(crate) restricted: Vec<Group>,
    pub(crate) app_container: bool,
    pub(crate) privileges: Vec<Privilege>,
    /// None means unavailable capture, never an empty attribute set.
    pub(crate) attributes: Option<token::attributes::Attributes>,
}

impl Subject {
    pub(crate) fn matches(&self, candidate: &[u8], deny: bool) -> bool {
        self.user == candidate
            || self.groups.iter().any(|group| {
                group.sid == candidate
                    && if deny {
                        group.attributes & (4 | 16) != 0
                    } else {
                        group.attributes & 4 != 0 && group.attributes & 16 == 0
                    }
            })
    }

    fn privilege(&self, luid: u64) -> bool {
        self.privileges
            .iter()
            .any(|privilege| privilege.luid == luid && privilege.attributes & 2 != 0)
    }
}

pub(crate) fn sid(bytes: &[u8]) -> Option<&[u8]> {
    if bytes.first() != Some(&1) || *bytes.get(1)? > 15 {
        return None;
    }
    bytes.get(..8 + usize::from(bytes[1]) * 4)
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Mapping(pub(crate) [u32; 4]);

impl Mapping {
    fn apply(self, mut access: u32) -> u32 {
        for (index, generic) in [0x8000_0000, 0x4000_0000, 0x2000_0000, 0x1000_0000]
            .into_iter()
            .enumerate()
        {
            if access & generic != 0 {
                access = (access & !generic) | self.0[index];
            }
        }
        access
    }
}

pub(crate) struct Descriptor<'a> {
    pub(crate) owner: &'a [u8],
    /// `None` is an absent or NULL DACL; an empty ACL has an eight-byte header.
    pub(crate) dacl: Option<&'a [u8]>,
}

struct Ace<'a> {
    deny: bool,
    inherit_only: bool,
    mask: u32,
    sid: &'a [u8],
}

fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(bytes.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}

fn aces(bytes: &[u8]) -> Option<Vec<Ace<'_>>> {
    if bytes.len() < 8
        || !matches!(bytes[0], 2 | 4)
        || bytes[1] != 0
        || usize::from(u16_at(bytes, 2)?) != bytes.len()
        || u16_at(bytes, 6)? != 0
    {
        return None;
    }
    let count = usize::from(u16_at(bytes, 4)?);
    if count > 4096 {
        return None;
    }
    let mut entries = Vec::with_capacity(count);
    let mut at: usize = 8;
    for _ in 0..count {
        let kind = *bytes.get(at)?;
        let flags = *bytes.get(at + 1)?;
        let size = usize::from(u16_at(bytes, at + 2)?);
        if !matches!(kind, 0 | 1) || flags & !0x1F != 0 || size < 16 || size % 4 != 0 {
            return None;
        }
        let ace = bytes.get(at..at.checked_add(size)?)?;
        let candidate = sid(ace.get(8..)?)?;
        if candidate.len() + 8 != ace.len() {
            return None;
        }
        // OWNER RIGHTS changes implicit-owner admission. Conditional/object
        // ACEs and this special principal require a separate measured contract.
        if candidate == [1, 1, 0, 0, 0, 0, 0, 3, 4, 0, 0, 0] {
            return None;
        }
        entries.push(Ace {
            deny: kind == 1,
            inherit_only: flags & 8 != 0,
            mask: u32_at(ace, 4)?,
            sid: candidate,
        });
        at += size;
    }
    // AclSize includes unused capacity after the final ACE. It is not an
    // assertion that every capacity byte belongs to a serialized ACE.
    Some(entries)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Evaluation {
    pub(crate) granted: u32,
    pub(crate) status: u32,
    pub(crate) privileges: [u64; 2],
    pub(crate) privilege_count: usize,
    /// Missing SeSecurityPrivilege does not publish the full privilege header.
    pub(crate) write_header: bool,
}

impl Evaluation {
    pub(crate) fn required_bytes(&self) -> u32 {
        (8 + 12 * self.privilege_count).max(20) as u32
    }

    pub(crate) fn privilege_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(8 + 12 * self.privilege_count);
        bytes.extend_from_slice(&(self.privilege_count as u32).to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        for &luid in &self.privileges[..self.privilege_count] {
            bytes.extend_from_slice(&luid.to_le_bytes());
            bytes.extend_from_slice(&0x8000_0000u32.to_le_bytes());
        }
        bytes
    }
}

/// O(A*S) time and O(A) bounded scratch for A<=4096 ACEs and S captured SIDs.
/// No host token query, native HANDLE, guest pointer or mutable state is used.
pub(crate) fn evaluate(
    subject: &Subject,
    descriptor: Descriptor<'_>,
    mapping: Mapping,
    desired: u32,
) -> Result<Evaluation, &'static str> {
    if subject.app_container || !subject.restricted.is_empty() {
        return Err("restricted or AppContainer access-check subject");
    }
    if desired & 0xF000_0000 != 0 {
        return Err("generic desired access was not mapped");
    }
    let entries = match descriptor.dacl {
        Some(bytes) => Some(aces(bytes).ok_or("nonclassic or malformed access-check DACL")?),
        None => None,
    };
    let mut result = Evaluation {
        granted: 0,
        status: 0,
        privileges: [0; 2],
        privilege_count: 0,
        write_header: true,
    };
    const SYSTEM_SECURITY: u32 = 0x0100_0000;
    const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
    const WRITE_OWNER: u32 = 0x0008_0000;
    let maximum = desired & MAXIMUM_ALLOWED != 0;
    let request = desired & !MAXIMUM_ALLOWED;
    if request & SYSTEM_SECURITY != 0 && !subject.privilege(8) {
        result.status = STATUS_PRIVILEGE_NOT_HELD;
        result.write_header = false;
        return Ok(result);
    }
    let mut granted = 0;
    // The measured private-token record orders TakeOwnership before Security.
    for (bit, luid) in [(WRITE_OWNER, 9), (SYSTEM_SECURITY, 8)] {
        if request & bit != 0 && subject.privilege(luid) {
            granted |= bit;
            result.privileges[result.privilege_count] = luid;
            result.privilege_count += 1;
        }
    }
    if subject.matches(descriptor.owner, false) {
        granted |= 0x0006_0000 & if maximum { u32::MAX } else { request };
    }
    if let Some(entries) = entries {
        let mut denied = 0;
        for ace in entries {
            if ace.inherit_only || !subject.matches(ace.sid, ace.deny) {
                continue;
            }
            let mask = mapping.apply(ace.mask) & !SYSTEM_SECURITY;
            if ace.deny {
                denied |= mask & !granted;
            } else {
                granted |= mask & !denied;
            }
        }
    } else {
        granted |= if maximum { mapping.0[3] } else { request };
    }
    if request & !granted != 0 || (if maximum { granted } else { request }) == 0 {
        result.status = STATUS_ACCESS_DENIED;
    } else {
        result.granted = if maximum { granted } else { request };
    }
    Ok(result)
}
