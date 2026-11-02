//! External device line routing retains independently generated software requests.
use super::*;

#[test]
fn external_spi_levels_preserve_software_pending_and_existing_irq_handles() {
    for count in [1, 2, 4] {
        let cluster = ArmCluster::new(count, 0x8000).unwrap();
        let line = {
            let mut gic = cluster.gic.lock().unwrap();
            gic.write_dist(0, 3);
            gic.set_group_enable(0, false, true);
            gic.set_group_enable(0, true, true);
            gic.set_enabled(40, true);
            gic.irq_line(0).unwrap()
        };
        cluster.set_irq_line(40, true).unwrap();
        cluster.gic.lock().unwrap().write_dist(0x204, 1 << 8);
        let saved = cluster.checkpoint().unwrap();
        cluster.set_irq_line(40, false).unwrap();
        assert!(line.load(Ordering::Acquire));
        cluster.gic.lock().unwrap().write_dist(0x284, 1 << 8);
        assert!(!line.load(Ordering::Acquire));
        cluster.restore_with(saved, || Ok(())).unwrap();
        assert!(line.load(Ordering::Acquire));
        assert!(Arc::ptr_eq(
            &line,
            &cluster.gic.lock().unwrap().irq_line(0).unwrap()
        ));
        cluster.set_irq_line(40, false).unwrap();
        assert!(line.load(Ordering::Acquire));
        cluster.set_irq_line(40, true).unwrap();
        cluster.gic.lock().unwrap().write_dist(0x284, 1 << 8);
        assert!(line.load(Ordering::Acquire));
        cluster.set_irq_line(40, false).unwrap();
        assert!(!line.load(Ordering::Acquire));
    }
}
