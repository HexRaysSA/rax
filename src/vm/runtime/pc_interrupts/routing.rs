//! Controller-only routing; native CPU callbacks occur after these locks drop.
use crate::devices::{ioapic::IoApic, lapic::LocalApic};
use crate::error::{Error, Result};

fn matches_destination(apic: &LocalApic, destination: u8, logical: bool) -> bool {
    if !logical {
        return destination == 0xff || apic.apic_id() == destination;
    }
    if destination == 0xff {
        return true;
    }
    let id = (apic.read_register(0xd0) >> 24) as u8;
    match apic.read_register(0xe0) >> 28 {
        0xf => id & destination != 0,
        0 => id & 0xf0 == destination & 0xf0 && id & destination & 0xf != 0,
        _ => false,
    }
}

/// Routing mutates only owned device models. A masked CPU keeps its accepted
/// vector in LAPIC IRR; a missing/disabled destination keeps the IOAPIC message.
pub(super) fn route_messages(
    ioapic: &mut IoApic,
    apics: &mut [std::sync::MutexGuard<'_, LocalApic>],
) -> Result<()> {
    for apic in apics.iter_mut() {
        while let Some(vector) = apic.take_pending_eoi() {
            ioapic.end_of_interrupt(vector);
        }
    }
    let mut index = 0;
    while let Some(message) = ioapic.pending_message(index) {
        let request = message.request;
        if !matches!(message.delivery_mode, 0 | 1 | 4) {
            return Err(Error::Emulator(format!(
                "I/O APIC delivery mode {} requires its complete platform contract",
                message.delivery_mode
            )));
        }
        if message.delivery_mode == 4 && request.level_triggered {
            return Err(Error::Emulator(
                "level-triggered I/O APIC NMI requires its complete platform contract".into(),
            ));
        }
        let selected = |apic: &LocalApic| {
            apic.is_enabled()
                && matches_destination(apic, request.destination, message.logical_destination)
        };
        let lowest = (message.delivery_mode == 1)
            .then(|| {
                apics
                    .iter()
                    .enumerate()
                    .filter(|(_, apic)| selected(apic))
                    .min_by_key(|(id, apic)| (apic.read_register(0xa0), apic.apic_id(), *id))
                    .map(|(id, _)| id)
            })
            .flatten();
        let mut accepted = false;
        for (id, apic) in apics.iter_mut().enumerate() {
            if !selected(apic) || (message.delivery_mode == 1 && lowest != Some(id)) {
                continue;
            }
            if message.delivery_mode == 4 {
                apic.set_pending_nmi();
                accepted = true;
            } else {
                accepted |=
                    apic.receive_external_interrupt(request.vector, request.level_triggered);
            }
        }
        if accepted {
            // The caller retains the I/O APIC lock, so the route cannot change
            // between observation and acceptance into the local-controller set.
            if !ioapic.accept_message(message) {
                return Err(Error::Emulator(
                    "I/O APIC accepted message changed while locked".into(),
                ));
            }
        } else {
            index += 1;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::devices::bus::MmioDevice;
    use std::sync::Mutex;

    fn program(
        io: &mut IoApic,
        pin: u8,
        vector: u8,
        mode: u8,
        destination: u8,
        logical: bool,
        level: bool,
    ) {
        io.write(0xfec0_0000, &[0x11 + pin * 2]);
        io.write(0xfec0_0010, &(u32::from(destination) << 24).to_le_bytes());
        let low = u32::from(vector)
            | (u32::from(mode) << 8)
            | (u32::from(logical) << 11)
            | (u32::from(level) << 15);
        io.write(0xfec0_0000, &[0x10 + pin * 2]);
        io.write(0xfec0_0010, &low.to_le_bytes());
    }

    fn route(io: &mut IoApic, controllers: &[Mutex<LocalApic>]) -> Result<()> {
        let mut guards = controllers
            .iter()
            .map(|apic| apic.lock().unwrap())
            .collect::<Vec<_>>();
        route_messages(io, &mut guards)
    }

    fn remote(io: &mut IoApic, pin: u8) -> bool {
        io.write(0xfec0_0000, &[0x10 + pin * 2]);
        let mut value = [0; 4];
        io.read(0xfec0_0010, &mut value);
        u32::from_le_bytes(value) & (1 << 14) != 0
    }

    #[test]
    fn level_messages_route_to_selected_cpus_and_eoi_reissues_only_asserted_sources() {
        for count in [1, 2, 4] {
            let controllers = (0..count)
                .map(|id| Mutex::new(LocalApic::new(id)))
                .collect::<Vec<_>>();
            let target = count as usize - 1;
            let mut io = IoApic::new();
            program(&mut io, 20, 0x51, 0, target as u8, false, true);
            io.set_irq(20, true);
            route(&mut io, &controllers).unwrap();
            assert!(io.pending().is_empty());
            assert!(remote(&mut io, 20));
            for (id, apic) in controllers.iter().enumerate() {
                assert_eq!(
                    apic.lock().unwrap().get_pending_vector(),
                    (id == target).then_some(0x51)
                );
            }
            {
                let mut apic = controllers[target].lock().unwrap();
                assert_eq!(apic.read_register(0x1a0), 1 << 17);
                apic.ack_interrupt(0x51);
                apic.write_register(0xb0, 0);
            }
            route(&mut io, &controllers).unwrap();
            assert_eq!(
                controllers[target].lock().unwrap().get_pending_vector(),
                Some(0x51)
            );
            assert!(remote(&mut io, 20));
            io.set_irq(20, false);
            {
                let mut apic = controllers[target].lock().unwrap();
                apic.ack_interrupt(0x51);
                apic.write_register(0xb0, 0);
            }
            route(&mut io, &controllers).unwrap();
            assert!(!remote(&mut io, 20));
            assert!(io.pending().is_empty());
            assert_eq!(
                controllers[target].lock().unwrap().get_pending_vector(),
                None
            );
        }
    }

    #[test]
    fn disabled_and_absent_destinations_retain_messages_without_blocking_other_pins() {
        let controllers = [Mutex::new(LocalApic::new(0)), Mutex::new(LocalApic::new(1))];
        controllers[1].lock().unwrap().write_register(0xf0, 0xff);
        let mut io = IoApic::new();
        for (pin, destination) in [(18, 7), (20, 1), (21, 0)] {
            program(&mut io, pin, 0x51, 0, destination, false, true);
            io.set_irq(pin, true);
        }
        route(&mut io, &controllers).unwrap();
        assert_eq!(io.pending().len(), 2);
        assert!(!remote(&mut io, 18));
        assert!(!remote(&mut io, 20));
        assert!(remote(&mut io, 21));
        controllers[1].lock().unwrap().write_register(0xf0, 0x1ff);
        route(&mut io, &controllers).unwrap();
        assert_eq!(io.pending().len(), 1);
        assert_eq!(io.pending()[0].gsi, 18);
        assert!(remote(&mut io, 20));
    }

    #[test]
    fn logical_flat_cluster_and_physical_broadcast_reach_the_selected_sets() {
        for (format, ids, destination, expected) in [
            (u32::MAX, [1, 2, 4, 8], 5, [true, false, true, false]),
            (
                0x0fff_ffff,
                [0x11, 0x12, 0x21, 0x22],
                0x13,
                [true, true, false, false],
            ),
        ] {
            let controllers = (0..4)
                .map(|id| {
                    let mut apic = LocalApic::new(id);
                    apic.write_register(0xd0, ids[id as usize] << 24);
                    apic.write_register(0xe0, format);
                    Mutex::new(apic)
                })
                .collect::<Vec<_>>();
            let mut io = IoApic::new();
            program(&mut io, 20, 0x51, 0, destination, true, false);
            io.set_irq(20, true);
            route(&mut io, &controllers).unwrap();
            for (id, apic) in controllers.iter().enumerate() {
                assert_eq!(
                    apic.lock().unwrap().get_pending_vector(),
                    expected[id].then_some(0x51)
                );
            }
            program(&mut io, 21, 0x61, 0, 0xff, false, false);
            io.set_irq(21, true);
            route(&mut io, &controllers).unwrap();
            assert!(
                controllers
                    .iter()
                    .all(|apic| apic.lock().unwrap().get_pending_vector() == Some(0x61))
            );
        }
    }

    #[test]
    fn lowest_priority_and_edge_nmi_use_their_distinct_local_controller_state() {
        let controllers = (0..4)
            .map(|id| {
                let mut apic = LocalApic::new(id);
                apic.write_register(0x80, [0x70, 0x60, 0x10, 0x50][id as usize]);
                Mutex::new(apic)
            })
            .collect::<Vec<_>>();
        let mut io = IoApic::new();
        program(&mut io, 20, 0x51, 1, 0xff, false, false);
        io.set_irq(20, true);
        route(&mut io, &controllers).unwrap();
        for (id, apic) in controllers.iter().enumerate() {
            assert_eq!(
                apic.lock().unwrap().get_pending_vector(),
                (id == 2).then_some(0x51)
            );
        }
        program(&mut io, 21, 0, 4, 1, false, false);
        io.set_irq(21, true);
        route(&mut io, &controllers).unwrap();
        assert!(controllers[1].lock().unwrap().has_pending_nmi());
        assert_eq!(controllers[1].lock().unwrap().get_pending_vector(), None);
        assert!(!remote(&mut io, 21));
    }

    #[test]
    fn unsupported_delivery_profiles_retain_their_source_message() {
        let controllers = [Mutex::new(LocalApic::new(0))];
        for mode in [2, 3, 5, 6, 7] {
            let mut io = IoApic::new();
            program(&mut io, 20, 0x51, mode, 0, false, false);
            io.set_irq(20, true);
            let original = io.pending().to_vec();
            assert!(route(&mut io, &controllers).is_err());
            assert_eq!(io.pending(), original);
            assert_eq!(controllers[0].lock().unwrap().get_pending_vector(), None);
        }
    }
}
