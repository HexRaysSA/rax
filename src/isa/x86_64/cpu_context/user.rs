//! Frozen user representation shared by RAXX8601 and the RAXX8602 base.

use crate::isa::x86_64::X86UserTrap;
use crate::isa::x86_64::user_mode::UserMode;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Serialize, Deserialize)]
struct LegacyUser {
    trap: Option<X86UserTrap>,
    compat: bool,
}

pub(super) fn serialize<S>(state: &Option<Box<UserMode>>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let legacy = state.as_ref().map(|state| {
        // Exhaustive classification prevents new runtime fields from silently
        // changing the frozen positional schema. The outer version carries
        // consumed debug status; trace suppression belongs to one attempt.
        let UserMode {
            trap,
            compat,
            step_suppressed: _,
            last_debug_status: _,
        } = state.as_ref();
        LegacyUser {
            trap: *trap,
            compat: *compat,
        }
    });
    legacy.serialize(serializer)
}

pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<Option<Box<UserMode>>, D::Error>
where
    D: Deserializer<'de>,
{
    let legacy = Option::<LegacyUser>::deserialize(deserializer)?;
    Ok(legacy.map(|state| {
        Box::new(UserMode {
            trap: state.trap,
            compat: state.compat,
            step_suppressed: false,
            last_debug_status: 0,
        })
    }))
}
