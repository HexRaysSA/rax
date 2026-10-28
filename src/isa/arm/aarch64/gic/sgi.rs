//! Affinity-aware SGI routing, including all-other-PE and range selectors.
use super::Gic;

impl Gic {
    pub(crate) fn raise_sgi_from(&mut self, source: usize, value: u64) {
        let intid = ((value >> 24) & 0xf) as u32;
        let all_others = value & (1 << 40) != 0;
        let aff1 = (value >> 16) & 0xff;
        let aff2 = (value >> 32) & 0xff;
        let aff3 = (value >> 48) & 0xff;
        let range = (value >> 44) & 0xf;
        let targets = value as u16;
        for (index, cpu) in self.cpu_interfaces.iter_mut().enumerate() {
            let affinity = cpu.affinity;
            let aff0 = affinity & 0xff;
            let selected = if all_others {
                index != source
            } else {
                (affinity >> 8) & 0xff == aff1
                    && (affinity >> 16) & 0xff == aff2
                    && (affinity >> 24) & 0xff == aff3
                    && aff0 / 16 == range
                    && targets & (1 << (aff0 % 16)) != 0
            };
            if selected {
                cpu.send_sgi(intid);
            }
        }
        self.update_all_cpus();
    }
}
