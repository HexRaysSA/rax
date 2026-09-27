//! The load configuration directory: the fields a loader consumes from
//! `IMAGE_LOAD_CONFIG_DIRECTORY32/64` (PE specification, "Load
//! Configuration Layout"). The structure grows over time; `Size` (its first
//! field) says how much of it the image carries, and fields past it read as
//! absent.

use super::{DataDirectory, PeKind, RvaFault, RvaSource};

/// The decoded fields.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LoadConfig {
    /// The first field: `Size` in `winnt.h` (the specification table names
    /// it `Characteristics`). Fields that end past it read as absent.
    pub size: u32,
    /// `SecurityCookie` VA (`/GS` cookie), if present.
    pub security_cookie: Option<u64>,
    /// `SEHandlerTable` VA (x86 SafeSEH), if present.
    pub se_handler_table: Option<u64>,
    /// `SEHandlerCount` (x86), if present.
    pub se_handler_count: Option<u64>,
    /// `GuardCFCheckFunctionPointer` VA, if present.
    pub guard_cf_check_function_pointer: Option<u64>,
    /// `GuardCFDispatchFunctionPointer` VA, if present.
    pub guard_cf_dispatch_function_pointer: Option<u64>,
    /// `GuardFlags`, if present.
    pub guard_flags: Option<u32>,
}

impl LoadConfig {
    /// Reads the load configuration of data directory `range`.
    pub fn read(
        src: &(impl RvaSource + ?Sized),
        kind: PeKind,
        range: DataDirectory,
    ) -> Result<Option<Self>, RvaFault> {
        if !range.is_present() {
            return Ok(None);
        }
        let at = range.extent_at(0, 4)?;
        let size = src.u32_at(at)?;
        let limit = u64::from(size.min(range.size));
        let wide = kind == PeKind::Pe32Plus;
        let w = kind.pointer_size() as u64;
        // (PE32 offset, PE32+ offset) from the specification table.
        let word = |off32: u64, off64: u64| -> Result<Option<u64>, RvaFault> {
            let off = if wide { off64 } else { off32 };
            if off + w > limit {
                return Ok(None);
            }
            src.word_at(kind, at + off).map(Some)
        };
        let guard_flags_off = if wide { 144 } else { 88 };
        let guard_flags = if guard_flags_off + 4 <= limit {
            Some(src.u32_at(at + guard_flags_off)?)
        } else {
            None
        };
        Ok(Some(LoadConfig {
            size,
            security_cookie: word(60, 88)?,
            se_handler_table: word(64, 96)?,
            se_handler_count: word(68, 104)?,
            guard_cf_check_function_pointer: word(72, 112)?,
            guard_cf_dispatch_function_pointer: word(76, 120)?,
            guard_flags,
        }))
    }
}
