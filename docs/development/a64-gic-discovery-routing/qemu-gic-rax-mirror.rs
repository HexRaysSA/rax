use rax::isa::arm::aarch64::gic::{Gic, GicConfig};
fn read64(gic: &Gic, offset: u64) -> u64 {
    u64::from(gic.read_dist(offset)) | (u64::from(gic.read_dist(offset + 4)) << 32)
}
fn main() {
    let mut gic = Gic::new(GicConfig {
        num_cpus: 4,
        ..Default::default()
    });
    println!("{:016x}", gic.read_dist(4));
    println!("{:016x}", gic.read_dist(0));
    gic.write_dist(0, 0x52);
    println!("{:016x}", gic.read_dist(0));
    println!("{:016x}", gic.read_dist(0x820));
    gic.write_dist(0x6100, 0x0012_3456);
    gic.write_dist(0x6104, 0x78);
    println!("{:016x}", read64(&gic, 0x6100));
    gic.write_dist(0x6104, 0xab);
    println!("{:016x}", read64(&gic, 0x6100));
    gic.write_dist(0x6100, 3);
    println!("{:016x}", read64(&gic, 0x6100));
    gic.write_dist(0x6104, 0);
    println!("{:016x}", read64(&gic, 0x6100));
    let mut highest = 0;
    for bank in 1..=(gic.read_dist(4) & 31) {
        let offset = 0x100 + u64::from(bank) * 4;
        gic.write_dist(offset, u32::MAX);
        let bits = gic.read_dist(offset);
        if bits != 0 {
            highest = 32 * bank + 31 - bits.leading_zeros();
        }
    }
    println!("{highest:016x}");
}
