//! Native Intel map ownership. All entries take a shared layout guard; map
//! changes take its exclusive guard. Backing lives at least as long as the VM.
use super::{
    bindings::*,
    memory_layout::{Layout, MapAccess, Mapping, Span},
};
use crate::devices::{bus::MmioRange, pci::PciStub};
use crate::error::{Error, Result};
use crate::vm::memory::GuestMemoryWrapper;
use std::sync::{Arc, Mutex, RwLock};
use vm_memory::{GuestAddress, GuestMemory, GuestMemoryMmap, GuestMemoryRegion};

pub(super) type Shared = Arc<RwLock<Option<Registered>>>;

pub(super) struct Registered {
    pub backing: Arc<GuestMemoryMmap>,
    reported: u64,
    fixed: Vec<Span>,
    pci: Option<Arc<Mutex<PciStub>>>,
    pub mapping: Mapping,
}
impl Registered {
    fn target(&self) -> Result<Layout> {
        let mut holes = self.fixed.clone();
        if let Some(pci) = &self.pci {
            for range in pci
                .lock()
                .map_err(|_| Error::Emulator("HVF PCI layout lock poisoned".into()))?
                .mmio_ranges()
            {
                holes.push(Span::new(range.base, range.len).map_err(Error::Emulator)?);
            }
        }
        Layout::new(self.reported, &holes).map_err(Error::Emulator)
    }
    fn synchronize(&mut self) -> Result<()> {
        let target = self.target()?;
        self.publish(target)
    }
    fn publish(&mut self, target: Layout) -> Result<()> {
        self.mapping
            .publish(
                target,
                &mut NativeMap {
                    memory: &self.backing,
                },
            )
            .map_err(Error::Emulator)
    }
    pub fn matches_backing(&self, memory: &GuestMemoryMmap) -> bool {
        self.backing
            .iter()
            .map(|r| (r.start_addr().0, r.len(), r.as_ptr() as usize))
            .eq(memory
                .iter()
                .map(|r| (r.start_addr().0, r.len(), r.as_ptr() as usize)))
    }
}

struct NativeMap<'a> {
    memory: &'a GuestMemoryMmap,
}
impl MapAccess for NativeMap<'_> {
    fn map(&mut self, span: Span) -> std::result::Result<(), String> {
        let region = self
            .memory
            .find_region(GuestAddress(span.start))
            .ok_or("HVF map has no backing")?;
        let offset = span.start - region.start_addr().0;
        if span.len() > region.len() - offset {
            return Err("HVF map crosses its backing region".into());
        }
        let size = usize::try_from(span.len()).map_err(|_| "HVF map size exceeds host width")?;
        // SAFETY: the retained mmap owns this checked region for the VM's
        // lifetime. Offset/size stay inside it; GPA/host offsets are page
        // aligned by Layout and GuestMemoryWrapper. The exclusive layout guard
        // excludes all native entry while SDK mappings change. SDK does not
        // retain this temporary Rust reference or unwind across the call.
        let result = unsafe {
            hv_vm_map(
                region.as_ptr().add(offset as usize).cast(),
                span.start,
                size,
                HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC,
            )
        };
        if result != HV_SUCCESS {
            return Err(format!(
                "HVF map {:#x}..{:#x}: {}",
                span.start,
                span.end,
                hv_error_string(result)
            ));
        }
        Ok(())
    }
    fn unmap(&mut self, span: Span) -> std::result::Result<(), String> {
        let size = usize::try_from(span.len()).map_err(|_| "HVF unmap size exceeds host width")?;
        // SAFETY: Span is a page-aligned subset of the current native mapping.
        // The exclusive layout guard excludes native access, and retained
        // backing remains live during removal and any rollback.
        let result = unsafe { hv_vm_unmap(span.start, size) };
        if result != HV_SUCCESS {
            return Err(format!(
                "HVF unmap {:#x}..{:#x}: {}",
                span.start,
                span.end,
                hv_error_string(result)
            ));
        }
        Ok(())
    }
}

pub(super) fn register(
    shared: &Shared,
    memory: &GuestMemoryWrapper,
    holes: &[MmioRange],
    pci: Option<Arc<Mutex<PciStub>>>,
) -> Result<()> {
    let mut guard = shared
        .write()
        .map_err(|_| Error::Emulator("HVF memory layout lock poisoned".into()))?;
    let fixed: Vec<Span> = holes
        .iter()
        .map(|r| Span::new(r.base, r.len))
        .collect::<std::result::Result<_, _>>()
        .map_err(Error::Emulator)?;
    if let Some(old) = guard.as_ref() {
        let same_pci = match (&old.pci, &pci) {
            (None, None) => true,
            (Some(left), Some(right)) => Arc::ptr_eq(left, right),
            _ => false,
        };
        if old.matches_backing(memory.memory())
            && old.reported == memory.size()
            && old.fixed == fixed
            && same_pci
        {
            return old.mapping.ready().map_err(Error::Emulator);
        }
        return Err(Error::InvalidConfig(
            "HVF memory is already registered with a different layout or backing".into(),
        ));
    }
    let mut registered = Registered {
        backing: Arc::new(memory.memory().clone()),
        reported: memory.size(),
        fixed,
        pci,
        mapping: Mapping::default(),
    };
    // Pure admission failure creates no SDK alias and must leave registration
    // absent, so a retry cannot mistake an unattempted map for a successful one.
    let target = registered.target()?;
    let result = registered.publish(target);
    // Retain backing and a potentially poisoned state even if SDK admission
    // fails. Dropping it early could leave an SDK alias pointing to freed RAM.
    *guard = Some(registered);
    result
}

pub(super) fn enter(shared: &Shared, id: hv_vcpuid_t) -> Result<hv_return_t> {
    loop {
        let guard = shared
            .read()
            .map_err(|_| Error::Emulator("HVF memory layout lock poisoned".into()))?;
        let memory = guard
            .as_ref()
            .ok_or_else(|| Error::InvalidConfig("HVF guest RAM is not registered".into()))?;
        memory.mapping.ready().map_err(Error::Emulator)?;
        if memory.target()? == memory.mapping.layout {
            // SAFETY: the caller owns this live SDK vCPU. The shared layout
            // guard retains backing and excludes map/unmap until entry exits.
            // No device/PCI lock is retained while guest code executes.
            return Ok(unsafe { hv_vcpu_run(id) });
        }
        drop(guard);
        let mut guard = shared
            .write()
            .map_err(|_| Error::Emulator("HVF memory layout lock poisoned".into()))?;
        guard
            .as_mut()
            .ok_or_else(|| Error::InvalidConfig("HVF guest RAM is not registered".into()))?
            .synchronize()?;
    }
}

/// Construction may precede registration. Only guest entry requires a live,
/// admitted mapping of the exact backing supplied to this CPU.
pub(super) fn validate_cpu_backing(shared: &Shared, memory: &GuestMemoryMmap) -> Result<()> {
    let guard = shared
        .read()
        .map_err(|_| Error::Emulator("HVF memory layout lock poisoned".into()))?;
    let registered = guard
        .as_ref()
        .ok_or_else(|| Error::InvalidConfig("HVF guest RAM is not registered".into()))?;
    registered.mapping.ready().map_err(Error::Emulator)?;
    if !registered.matches_backing(memory) {
        return Err(Error::InvalidConfig(
            "HVF CPU backing differs from registered RAM".into(),
        ));
    }
    Ok(())
}
