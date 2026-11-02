//! Fixed per-user policy roots, selected only from the captured primary SID.
use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum UserPolicyRoot {
    Safer,
    System,
}

impl UserPolicyRoot {
    pub(crate) const ALL: [Self; 2] = [Self::Safer, Self::System];

    pub(super) fn suffix(self) -> &'static str {
        match self {
            Self::Safer => POLICY_SUFFIX,
            Self::System => "\\Software\\Policies\\Microsoft\\Windows\\System",
        }
    }

    pub(crate) fn path(self, sid: &[u8]) -> io::Result<Vec<u16>> {
        Ok(user_hive_path(sid)?
            .into_iter()
            .chain(self.suffix().encode_utf16())
            .collect())
    }
}

pub(crate) fn user_policy_path(sid: &[u8]) -> io::Result<Vec<u16>> {
    UserPolicyRoot::Safer.path(sid)
}

pub(super) const POLICY_SUFFIX: &str =
    "\\Software\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers";

pub(super) fn user_hive_path(sid: &[u8]) -> io::Result<Vec<u16>> {
    if super::super::security::sid(sid) != Some(sid) {
        return Err(invalid("invalid primary SID for runtime policy selection"));
    }
    let authority = sid[2..8]
        .iter()
        .fold(0u64, |n, &byte| (n << 8) | u64::from(byte));
    let authority = if authority > u64::from(u32::MAX) {
        format!("0x{authority:X}")
    } else {
        authority.to_string()
    };
    let mut text = format!("S-1-{authority}");
    for subauthority in sid[8..].chunks_exact(4) {
        let value = u32::from_le_bytes(subauthority.try_into().unwrap());
        text.push_str(&format!("-{value}"));
    }
    Ok(format!("\\Registry\\User\\{text}").encode_utf16().collect())
}

impl Registry {
    pub(crate) fn with_user_policy(self, sid: &[u8], tree: Option<KeyTree>) -> io::Result<Self> {
        self.with_user_policy_root(UserPolicyRoot::Safer, sid, tree)
    }

    pub(crate) fn with_user_policy_root(
        mut self,
        root: UserPolicyRoot,
        sid: &[u8],
        tree: Option<KeyTree>,
    ) -> io::Result<Self> {
        if self.upcase.len() != 65_536 || self.user_policies.contains_key(&root) {
            return Err(invalid(
                "invalid or duplicate per-user runtime policy selection",
            ));
        }
        let path = root.path(sid)?;
        self.check_primary_hive_sid(sid)?;
        let folded: Vec<_> = path.iter().map(|&u| self.upcase[usize::from(u)]).collect();
        if let Some(tree) = tree {
            let key = tree::build(
                self.upcase.clone(),
                path,
                tree,
                0,
                &mut self.value_budget()?,
                &mut tree::TreeBudget::default(),
                None,
            )?;
            self.keys.insert(folded.clone(), key);
        }
        self.user_policies.insert(root, folded.into());
        self.link_primary_hive_policy()?;
        Ok(self)
    }
}
