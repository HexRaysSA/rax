//! Keep a saved LAPIC countdown inert until the stopped VM enters KVM.
use crate::error::{Error, Result};
use kvm_bindings::kvm_lapic_state;
use kvm_ioctls::VcpuFd;

const LVT_TIMER: usize = 0x320;
const INITIAL_COUNT: usize = 0x380;
const CURRENT_COUNT: usize = 0x390;
const DIVIDE_CONFIG: usize = 0x3e0;
const MODE_MASK: u32 = 3 << 17;
const PERIODIC: u32 = 1 << 17;

fn read(lapic: &kvm_lapic_state, offset: usize) -> u32 {
    u32::from_le_bytes(std::array::from_fn(|byte| lapic.regs[offset + byte] as u8))
}

fn write(lapic: &mut kvm_lapic_state, offset: usize, value: u32) {
    lapic.regs[offset..offset + 4].copy_from_slice(&value.to_le_bytes().map(|byte| byte as i8));
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::backend::kvm) struct Countdown {
    apic_base: u64,
    lvt: u32,
    divider: u32,
    initial: u32,
    current: u32,
}

impl Countdown {
    pub(super) fn capture(lapic: &kvm_lapic_state, apic_base: u64) -> Option<Self> {
        let lvt = read(lapic, LVT_TIMER);
        let initial = read(lapic, INITIAL_COUNT);
        let current = read(lapic, CURRENT_COUNT);
        // A zero current count needs separate admission: it can conceal a
        // pending expiry, or denote an already delivered one-shot.
        (matches!(lvt & MODE_MASK, 0 | PERIODIC) && initial != 0 && current != 0).then(|| Self {
            apic_base,
            lvt,
            divider: read(lapic, DIVIDE_CONFIG),
            initial,
            current,
        })
    }

    pub(super) fn disarm(lapic: &mut kvm_lapic_state) {
        write(lapic, INITIAL_COUNT, 0);
        write(lapic, CURRENT_COUNT, 0);
    }

    pub(super) fn restore_into(self, lapic: &mut kvm_lapic_state, apic_base: u64) -> Result<()> {
        if self.apic_base != apic_base
            || self.lvt != read(lapic, LVT_TIMER)
            || self.divider != read(lapic, DIVIDE_CONFIG)
            || read(lapic, INITIAL_COUNT) != 0
            || read(lapic, CURRENT_COUNT) != 0
        {
            return Err(Error::InvalidConfig(
                "native KVM stopped LAPIC countdown changed before entry".into(),
            ));
        }
        write(lapic, INITIAL_COUNT, self.initial);
        write(lapic, CURRENT_COUNT, self.current);
        Ok(())
    }
}

/// Merge the saved phase into the current controller, retaining any IRQs
/// latched after bank installation. Preflight every CPU before the first
/// caller writes a native bank or advances a clock.
pub(in crate::backend::kvm) fn prepare_countdowns<'a>(
    cpus: &[(u32, &'a VcpuFd)],
    countdowns: &[Option<Countdown>],
) -> Result<Vec<(&'a VcpuFd, kvm_lapic_state)>> {
    if cpus.len() != countdowns.len() {
        return Err(Error::InvalidConfig(
            "native KVM countdown CPU set differs".into(),
        ));
    }
    let mut prepared = Vec::new();
    for ((_, cpu), countdown) in cpus.iter().copied().zip(countdowns) {
        if let Some(countdown) = countdown {
            let mut lapic = cpu.get_lapic()?;
            countdown.restore_into(&mut lapic, cpu.get_sregs()?.apic_base)?;
            prepared.push((cpu, lapic));
        }
    }
    Ok(prepared)
}
