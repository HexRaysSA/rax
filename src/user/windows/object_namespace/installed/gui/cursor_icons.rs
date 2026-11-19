//! Capture fixed stock resource requests on the converted native GUI helper.
use super::{GetProcAddress, Handle, Module};
use crate::user::windows::gui::cursor_icons::{CURSOR, Catalog, ICON, MODULE, Resource};

const CURSORS: &[u16] = &[
    32512, 32513, 32514, 32515, 32516, 32640, 32641, 32642, 32643, 32644, 32645, 32646, 32648,
    32649, 32650, 32651, 32671, 32672,
];
const ICONS: &[u16] = &[32512, 32513, 32514, 32515, 32516, 32517, 32518];

#[repr(C)]
struct Name {
    length: u16,
    maximum: u16,
    buffer: usize,
}

#[repr(C)]
struct Request {
    hint: usize,
    selector: u32,
    format: [u32; 3],
}

type Query = unsafe extern "system" fn(*const Name, *const Name, *const Request) -> Handle;

fn capture(query: Query) -> Result<Catalog, String> {
    let width = std::mem::size_of_val(&MODULE) as u16;
    let module = Name {
        length: width,
        maximum: width,
        buffer: MODULE.as_ptr() as usize,
    };
    let mut resources = Vec::new();
    for (ordinals, selector) in [(CURSORS, CURSOR), (ICONS, ICON)] {
        for &ordinal in ordinals {
            let resource = Name {
                length: 0,
                maximum: 0,
                buffer: usize::from(ordinal),
            };
            let read = |format| {
                let request = Request {
                    hint: 0,
                    selector,
                    format,
                };
                // SAFETY: static installed export on the converted helper,
                // live native-layout stack records, and fixed stock identifiers.
                // The service is a query and has no guest-controlled argument.
                unsafe { query(&module, &resource, &request) as usize }
            };
            let handle = read([0; 3]);
            if handle == 0 {
                continue;
            }
            let mut depths = 0;
            for depth in 1..=32 {
                if read([0, 0, depth]) == handle {
                    depths |= 1 << (depth - 1);
                }
            }
            let any_format = read([1; 3]) == handle && read([u32::MAX; 3]) == handle;
            // Default-priority observations are captured as ordering only.
            resources.push((
                handle,
                Resource {
                    ordinal,
                    selector,
                    depths,
                    any_format,
                },
            ));
        }
    }
    resources.sort_unstable_by_key(|&(handle, _)| handle);
    if resources.is_empty() || resources.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err("unrecognized native cursor/icon cache identities".into());
    }
    Ok(Catalog::new(
        resources.into_iter().map(|(_, entry)| entry).collect(),
    ))
}

pub(super) fn capture_stable(win32u: &Module) -> Result<Catalog, String> {
    // The selected GUI snapshot already admits only native 64-bit layouts.
    if std::mem::size_of::<Name>() != 16 || std::mem::size_of::<Request>() != 24 {
        return Err("selected Win32u cursor/icon ABI requires 64-bit records".into());
    }
    // SAFETY: live selected module, terminated static export name and
    // the recovered native 64-bit ABI for this fixed export.
    let address = unsafe { GetProcAddress(win32u.0, c"NtUserFindExistingCursorIcon".as_ptr()) };
    if address.is_null() {
        return Err("selected Win32u has no NtUserFindExistingCursorIcon".into());
    }
    let query: Query = unsafe { std::mem::transmute(address) };
    let catalog = capture(query)?;
    if catalog != capture(query)? {
        return Err("native cursor/icon cache changed during capture".into());
    }
    Ok(catalog)
}
