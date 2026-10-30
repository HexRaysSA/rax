use super::*;
const BASE: u64 = 0x4000_0000;
const SIZE: u64 = 0x2000;
fn start(power: &mut Power, id: u64) -> u64 {
    power.cpu_on(id, BASE, 0xface, true, BASE, SIZE)
}

#[test]
fn native_power_transitions_remain_pending_until_individual_acknowledgements() {
    let mut power = Power::new(4);
    assert_eq!(
        power.states,
        [State::On, State::Off, State::Off, State::Off]
    );
    for id in [3, 1, 2] {
        assert_eq!(start(&mut power, id), 0);
    }
    assert_eq!(power.affinity_info(1, 0), 2);
    assert_eq!(start(&mut power, 1), -5i64 as u64);
    power.validate(4, BASE, SIZE).unwrap();
    let original = power.pending.clone();
    // Two inspections do not consume requests; failure before any ack loses none.
    assert_eq!(power.pending, original);
    power.complete(1, true).unwrap();
    assert_eq!(
        power
            .pending
            .iter()
            .map(|p| match p.request {
                CpuPowerRequest::Start { cpu_id, .. } => cpu_id,
                _ => panic!(),
            })
            .collect::<Vec<_>>(),
        [3, 2]
    );
    assert_eq!(start(&mut power, 1), -4i64 as u64);
    power.cpu_off(1).unwrap();
    assert_eq!(power.affinity_info(1, 0), 0);
    assert_eq!(start(&mut power, 1), -4i64 as u64);
    power.complete(1, false).unwrap();
    assert_eq!(power.affinity_info(1, 0), 1);
    assert_eq!(start(&mut power, 1), 0);
    power.validate(4, BASE, SIZE).unwrap();
}

#[test]
fn native_power_rejects_reserved_affinities_wrapping_unaligned_and_outside_entries() {
    let mut power = Power::new(2);
    for target in [2, 255, 256, 1 << 24, 1 << 31, 1 << 32, u64::MAX] {
        assert_eq!(start(&mut power, target), INVALID_PARAMETERS);
    }
    for entry in [0, BASE - 4, BASE + 1, BASE + SIZE, u64::MAX - 3] {
        assert_eq!(
            power.cpu_on(1, entry, 0, false, BASE, SIZE),
            INVALID_ADDRESS
        );
    }
    assert!(power.pending.is_empty());
    assert_eq!(power.affinity_info(1, 1), INVALID_PARAMETERS);
    assert_eq!(power.affinity_info(u64::MAX, 0), INVALID_PARAMETERS);
    assert_eq!(
        power.cpu_on(1, BASE + SIZE - 4, u64::MAX, false, BASE, SIZE),
        0
    );
    power.validate(2, BASE, SIZE).unwrap();
}

#[test]
fn native_power_graph_rejects_missing_duplicate_mismatched_and_unbounded_requests() {
    let mut power = Power::new(2);
    assert_eq!(start(&mut power, 1), 0);
    let mut bad = power.clone();
    bad.pending.clear();
    assert!(bad.validate(2, BASE, SIZE).is_err());
    let mut bad = power.clone();
    bad.pending.push(bad.pending[0].clone());
    assert!(bad.validate(2, BASE, SIZE).is_err());
    let mut bad = power.clone();
    bad.states[1] = State::Off;
    assert!(bad.validate(2, BASE, SIZE).is_err());
    let mut bad = power.clone();
    bad.pending[0].request = CpuPowerRequest::Off { cpu_id: 1 };
    assert!(bad.validate(2, BASE, SIZE).is_err());
    let mut bad = power.clone();
    bad.pending[0].request = CpuPowerRequest::Start {
        cpu_id: 2,
        entry: BASE,
        context: 0,
        pstate: ENTRY_PSTATE,
    };
    assert!(bad.validate(2, BASE, SIZE).is_err());
    assert!(power.complete(1, false).is_err());
    assert!(power.start_endianness(1, BASE, 0, ENTRY_PSTATE).is_err());
    assert!(
        power
            .start_endianness(1, BASE, 0xface, ENTRY_PSTATE)
            .unwrap()
    );
    power.validate_online(&[true, false]).unwrap();
    assert!(power.validate_online(&[true, true]).is_err());
    power.complete(1, true).unwrap();
    assert!(power.validate_online(&[true, false]).is_err());
    power.validate_online(&[true, true]).unwrap();
    assert!(power.complete(1, true).is_err());
}

#[test]
fn native_power_pending_requests_and_global_shutdown_survive_codec() {
    let mut power = Power::new(4);
    for id in 1..4 {
        assert_eq!(start(&mut power, id), 0);
    }
    power.shutdown = true;
    let raw = crate::codec::serialize(&power).unwrap();
    let restored: Power = crate::codec::deserialize(&raw).unwrap();
    assert_eq!(restored, power);
    restored.validate(4, BASE, SIZE).unwrap();
}
