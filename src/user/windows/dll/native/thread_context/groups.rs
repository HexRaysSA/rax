use super::WinArch;
use std::ops::Range;

pub(super) fn flags_offset(arch: WinArch) -> u64 {
    if arch == WinArch::X64 { 48 } else { 0 }
}

pub(super) fn has_debug(arch: WinArch, flags: u32) -> bool {
    flags & if arch == WinArch::Arm64 { 8 } else { 16 } != 0
}

pub(super) fn debug_range(arch: WinArch) -> Range<usize> {
    crate::user::windows::context::debug::context_range(arch)
}

pub(super) fn information(arch: WinArch, flags: u32, reported: u32) -> u32 {
    if arch == WinArch::X86 {
        return if flags & 0x4000_0000 != 0 {
            flags & 0xd800_0000
        } else {
            0
        };
    }
    flags & 0x2000_0000
        | if flags & 0x4000_0000 != 0 {
            0xc000_0000 | reported
        } else {
            0
        }
}

pub(super) fn returned_flags(arch: WinArch, flags: u32, reported: u32) -> u32 {
    information(arch, flags, reported)
        | match arch {
            WinArch::Arm64 => flags & 0xdf | 0x0040_0000,
            WinArch::X86 => flags & 0x3f | 0x0001_0000,
            WinArch::X64 => flags & 0x1f | 0x0010_0000,
        }
}

/// ABI field ranges; reserved bytes and unselected groups remain untouched.
/// Work and storage are bounded by the fixed CONTEXT structure size.
pub(super) fn ranges(arch: WinArch, flags: u32) -> Vec<Range<usize>> {
    let mut ranges = Vec::new();
    let mut add = |bit, selected: &[Range<usize>]| {
        if flags & bit != 0 {
            ranges.extend_from_slice(selected);
        }
    };
    match arch {
        WinArch::Arm64 => {
            add(1, &[4..8, 240..272]);
            add(2, &[8..152, 160..240]);
            add(4, &[272..792]);
            add(8, &[792..912]);
            add(16, &[152..160]);
            if flags & 4 == 0 {
                add(64, &[272..528, 784..792]);
                add(128, &[528..784]);
            }
        }
        WinArch::X86 => {
            add(1, &[180..204]);
            add(2, &[156..180]);
            add(4, &[140..156]);
            add(8, &[28..140]);
            add(16, &[4..28]);
            add(32, &[204..492]);
        }
        WinArch::X64 => {
            add(1, &[56..58, 66..72, 152..160, 248..256]);
            add(2, &[120..152, 160..248]);
            add(4, &[58..66]);
            add(8, &[52..56, 256..672]);
            add(16, &[72..120]);
        }
    }
    ranges
}
