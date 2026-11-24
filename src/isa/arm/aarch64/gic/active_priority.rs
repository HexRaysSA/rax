//! Physical active-priority registers for the eight-priority-bit CPU interface.
use super::{CpuInterface, Gic};

pub(super) fn running_priority(registers: &[[u32; 4]; 2]) -> u8 {
    registers[0]
        .iter()
        .zip(&registers[1])
        .enumerate()
        .find_map(|(index, (group0, group1))| {
            let word = group0 | group1;
            (word != 0).then(|| index as u8 * 64 + word.trailing_zeros() as u8 * 2)
        })
        .unwrap_or(0xff)
}

pub(super) fn set_priority_bit(registers: &mut [[u32; 4]; 2], group: u8, priority: u8) {
    if let Some(bank) = registers.get_mut(usize::from(group)) {
        let rank = usize::from(priority >> 1);
        bank[rank / 32] |= 1 << (rank % 32);
    }
}

impl CpuInterface {
    pub(super) fn activate_priority(&mut self, group: u8, priority: u8) {
        set_priority_bit(&mut self.active_priority_registers, group, priority);
        self.running_priority = running_priority(&self.active_priority_registers);
    }

    pub(super) fn drop_active_priority(&mut self, group: u8) {
        if let Some(bank) = self.active_priority_registers.get_mut(usize::from(group))
            && let Some(word) = bank.iter_mut().find(|word| **word != 0)
        {
            // EOIR drops the highest active priority in the addressed group.
            // The distributor's active state is changed separately for EOImode 0.
            *word &= *word - 1;
        }
        self.running_priority = running_priority(&self.active_priority_registers);
    }

    pub(crate) fn active_priority_register(&self, group: usize, index: usize) -> u32 {
        self.active_priority_registers[group][index]
    }
}

impl Gic {
    pub(crate) fn write_active_priority_register(
        &mut self,
        cpu_id: usize,
        group: usize,
        index: usize,
        value: u32,
    ) {
        if let Some(cpu) = self.cpu_mut(cpu_id) {
            cpu.active_priority_registers[group][index] = value;
            cpu.running_priority = running_priority(&cpu.active_priority_registers);
            self.update_all_cpus();
        }
    }
}
