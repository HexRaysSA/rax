//! Guest-register boundary regressions, also compiled against the parent controller.
use super::S5lNand;

#[test]
fn fifo_count_outside_page_returns_zero_without_host_underflow() {
    for count in [2048, 2049, u32::MAX] {
        let mut nand = S5lNand::new(None);
        nand.set_bank(0);
        nand.write(0x30, count);
        assert_eq!(nand.read(0x80), 0, "count={count:#x}");
        assert_eq!(nand.fmdnum, count.wrapping_sub(4));
    }
}

#[test]
fn invalid_dma_bank_deasserts_selection_without_host_shift_panic() {
    for bank in [8, 31, 32, u32::MAX] {
        let mut nand = S5lNand::new(None);
        nand.set_bank(0);
        nand.set_bank(bank);
        assert_eq!(nand.fmctrl0 & 0x1fe, 0, "bank={bank:#x}");
    }
}
