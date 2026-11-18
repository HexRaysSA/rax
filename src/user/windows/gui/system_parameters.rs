//! Fixed desktop settings selected during native GUI acquisition.

pub(crate) const GET_NONCLIENT_METRICS: u32 = 0x29;
pub(crate) const GET_HIGH_CONTRAST: u32 = 0x42;
pub(crate) const GET_MOUSE_HOVER_TIME: u32 = 0x66;
pub(crate) const GET_WHEEL_SCROLL_LINES: u32 = 0x68;

pub(crate) const NONCLIENT_METRICS_SIZE: usize = 500;
pub(crate) const HIGH_CONTRAST_SCHEME_UNITS: usize = 128;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Snapshot {
    pub(crate) wheel_scroll_lines: u32,
    pub(crate) mouse_hover_time: u32,
    pub(crate) nonclient_metrics: [u8; NONCLIENT_METRICS_SIZE - 4],
    pub(crate) high_contrast_flags: u32,
    pub(crate) high_contrast_scheme: [u16; HIGH_CONTRAST_SCHEME_UNITS],
}
