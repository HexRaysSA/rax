//! Immutable installed image-section identity with lazy kernel-view acquisition.
use super::*;
use std::sync::OnceLock;
const ALL: u32 = 0x000F_001F;
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum GrantError {
    Status(u32),
    Unavailable(&'static str),
}
#[derive(Debug)]
enum Access {
    Selected(CapturedSection),
    Created { system_security: Option<u32> },
}
#[derive(Debug, Clone, Copy)]
pub(crate) struct CapturedSection {
    pub(crate) maximum_access: u32,
    pub(crate) system_security_status: u32,
    pub(crate) attributes: u32,
    pub(crate) size: u64,
    pub(crate) force_case_insensitive: bool,
}
impl CapturedSection {
    pub(super) fn valid(&self) -> bool {
        self.maximum_access & 1 != 0
            && self.maximum_access & !ALL == 0
            && matches!(
                self.system_security_status,
                0 | STATUS_PRIVILEGE_NOT_HELD | STATUS_ACCESS_DENIED
            )
            && self.attributes == 0x0180_0000
            && (1..=0x7FFF_FFFF).contains(&self.size)
    }
}
/// Selected kernel image-section metadata with a guest-owned reference lifetime.
#[derive(Debug)]
pub struct ImageSection {
    pub(crate) path: Vec<u16>,
    pub(crate) attributes: u32,
    pub(crate) size: u64,
    pub(crate) image_size: u64,
    access: Access,
    _file: Option<Arc<crate::user::windows::fs::FileLifetime>>,
    pub(super) image: OnceLock<Result<Arc<ImageTemplate>, String>>,
    #[cfg(windows)]
    projected_x64: OnceLock<Result<Arc<ImageTemplate>, String>>,
    #[cfg(windows)]
    pub(super) source: OnceLock<Arc<super::installed::image::Source>>,
}
impl ImageSection {
    #[cfg(windows)]
    pub(crate) fn mapped_filename(&self) -> Option<io::Result<Vec<u16>>> {
        self.source.get().map(|source| source.mapped_filename())
    }

    #[cfg(test)]
    pub(crate) fn with_test_image(image: Arc<ImageTemplate>) -> Arc<Self> {
        let section = Self::selected(
            "\\KnownDlls\\fixture.dll".encode_utf16().collect(),
            CapturedSection {
                maximum_access: ALL,
                system_security_status: STATUS_PRIVILEGE_NOT_HELD,
                attributes: 0x0180_0000,
                size: image.bytes.len() as u64,
                force_case_insensitive: true,
            },
        );
        section.image.set(Ok(image)).unwrap();
        section
    }
    pub(super) fn selected(path: Vec<u16>, access: CapturedSection) -> Arc<Self> {
        Arc::new(Self {
            path,
            attributes: access.attributes,
            size: access.size,
            image_size: access.size,
            access: Access::Selected(access),
            _file: None,
            image: OnceLock::new(),
            #[cfg(windows)]
            projected_x64: OnceLock::new(),
            #[cfg(windows)]
            source: OnceLock::new(),
        })
    }
    pub(crate) fn image(&self) -> io::Result<Arc<ImageTemplate>> {
        self.image
            .get_or_init(|| {
                #[cfg(windows)]
                if let Some(source) = self.source.get() {
                    return source.image().map_err(|error| error.to_string());
                }
                Err("selected image section has no pinned native backing".to_owned())
            })
            .clone()
            .map_err(|error| invalid(&error))
    }
    pub(crate) fn image_for(
        &self,
        arch: crate::user::windows::arch::WinArch,
    ) -> io::Result<Arc<ImageTemplate>> {
        let image = self.image()?;
        #[cfg(windows)]
        if arch == crate::user::windows::arch::WinArch::X64
            && image.machine == 0xAA64
            && let Some(source) = self.source.get()
        {
            return self
                .projected_x64
                .get_or_init(|| {
                    source
                        .image_machine(0x8664)
                        .map_err(|error| error.to_string())
                })
                .clone()
                .map_err(|error| invalid(&error));
        }
        let _ = arch;
        Ok(image)
    }
    pub(crate) fn created(
        backing: super::file_image::Backing,
        file: Arc<crate::user::windows::fs::FileLifetime>,
        system_security: Option<u32>,
    ) -> Arc<Self> {
        let template = backing.template;
        let section = Arc::new(Self {
            path: Vec::new(),
            attributes: backing.attributes,
            size: backing.maximum,
            image_size: template.bytes.len() as u64,
            access: Access::Created { system_security },
            _file: Some(file),
            image: OnceLock::new(),
            #[cfg(windows)]
            projected_x64: OnceLock::new(),
            #[cfg(windows)]
            source: OnceLock::new(),
        });
        section.image.set(Ok(template)).expect("new image slot");
        #[cfg(windows)]
        if let Some(source) = backing.source {
            section.source.set(source).expect("new native image source");
        }
        section
    }
    pub(crate) fn grant(&self, access: u32, duplicate: bool) -> Result<u32, GrantError> {
        match self.access {
            Access::Selected(captured) => grant(
                captured.maximum_access,
                captured.system_security_status,
                access,
                duplicate,
            )
            .map_err(GrantError::Status),
            Access::Created { system_security } => {
                // NtDuplicateObject does not expand MAXIMUM_ALLOWED, even for
                // a creator-owned object. The constructor does expand it.
                super::file_image::grant(
                    if duplicate {
                        access & !0x0200_0000
                    } else {
                        access
                    },
                    system_security,
                )
            }
        }
    }
}
impl Namespace {
    /// The direct-root WoW64 conversion belongs to the process's CHPE profile,
    /// not just the host architecture. Acquisition captures the default ARM64
    /// profile; a pure x86 runtime disables it without changing native_machine
    /// or removing the explicitly addressable CHPE directory and its images.
    pub(crate) fn select_wow_section_root(&mut self, chpe: bool) -> io::Result<()> {
        let root = if chpe {
            match self.lookup(
                None,
                &"\\KnownDllsChpe32".encode_utf16().collect::<Vec<_>>(),
                0x40,
            ) {
                Ok(d) => Some(d),
                Err(LookupError::Status(STATUS_OBJECT_NAME_NOT_FOUND)) => None,
                Err(_) => return Err(invalid("selected ARM64 CHPE namespace is unavailable")),
            }
        } else {
            None
        };
        self.wow_section_root = root;
        Ok(())
    }
    pub(crate) fn lookup_section(
        &self,
        root: Option<Arc<Directory>>,
        name: &[u16],
        flags: u32,
        wow: bool,
    ) -> Result<Arc<ImageSection>, LookupError> {
        match self.lookup_installed_section(root, name, flags, wow)? {
            SelectedSection::Image(section) => Ok(section),
            SelectedSection::Data(_) => Err(LookupError::Unselected),
        }
    }
}

pub(super) fn grant(
    maximum_access: u32,
    system_security_status: u32,
    access: u32,
    duplicate: bool,
) -> Result<u32, u32> {
    let mut requested = access & 0x0DFF_FFFF;
    if duplicate {
        requested &= !0xFFE0;
    }
    for (generic, specific) in [
        (0x8000_0000, 0x0002_0005),
        (0x4000_0000, 0x0002_0002),
        (0x2000_0000, 0x0002_0008),
        (0x1000_0000, ALL),
    ] {
        if access & generic != 0 {
            requested |= specific;
        }
    }
    if requested & !(ALL | 0x0100_0000) != 0 || requested & ALL & !maximum_access != 0 {
        return Err(STATUS_ACCESS_DENIED);
    }
    if requested & 0x0100_0000 != 0 && system_security_status != 0 {
        return Err(system_security_status);
    }
    if !duplicate && access & 0x0200_0000 != 0 {
        requested |= maximum_access;
    }
    if !duplicate && requested == 0 {
        return Err(STATUS_ACCESS_DENIED);
    }
    Ok(requested)
}
