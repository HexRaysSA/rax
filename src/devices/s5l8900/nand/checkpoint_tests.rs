//! Component tests use owned synthetic files and explicit logical observations.
use super::*;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const LIMIT: usize = 4 * 1024 * 1024;
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "rax-nand-checkpoint-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        Self(root)
    }
    fn page(&self, bank: u32, name: &str, data: &[u8]) {
        let root = self.0.join(format!("bank{bank}"));
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join(name), data).unwrap();
    }
    fn controller(&self) -> S5lNand {
        let mut nand = S5lNand::new(Some(self.0.clone()));
        nand.policy = Some(NandPolicy {
            bbt_all_good: false,
            bbt_good_upto: None,
            rewrite_pmbr: false,
            fdisk_relsect: None,
            fdisk_numsect: None,
        });
        nand
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn roundtrip(nand: &S5lNand) -> S5lNand {
    let bytes = nand.capture_checkpoint(LIMIT).unwrap();
    let restored = S5lNand::from_checkpoint(&bytes, LIMIT).unwrap();
    assert_eq!(restored.capture_checkpoint(LIMIT).unwrap(), bytes);
    restored
}
fn select(nand: &mut S5lNand, bank: u32, page: u32) {
    nand.set_bank(bank);
    nand.set_buffered_page(page);
}
fn context_page() -> Vec<u8> {
    let mut bytes = vec![0; NAND_BYTES_PER_PAGE + NAND_BYTES_PER_SPARE];
    bytes[NAND_BYTES_PER_PAGE + 9] = NAND_VFL_CONTEXT_SPARE_TYPE;
    bytes
}

#[test]
fn unread_pages_empty_files_missing_pages_and_tail_truncation_survive_backing_removal() {
    let f = Fixture::new();
    for bank in 0..NAND_NUM_BANKS {
        f.page(bank, "0.page", &[bank as u8 + 1; 3]);
        f.page(bank, "1.page", &[]);
        f.page(bank, "4294967295.page", &vec![bank as u8 + 17; 8192]);
    }
    let original = f.controller();
    let bytes = original.capture_checkpoint(LIMIT).unwrap();
    assert_eq!(original.buffered_bank, -1);
    assert!(
        original
            .sparse_vfl_context_blocks
            .iter()
            .all(Option::is_none)
    );
    for bank in 0..NAND_NUM_BANKS {
        fs::remove_dir_all(f.0.join(format!("bank{bank}"))).unwrap();
    }
    let mut nand = S5lNand::from_checkpoint(&bytes, LIMIT).unwrap();
    for bank in 0..NAND_NUM_BANKS {
        select(&mut nand, bank, 0);
        assert_eq!(
            &nand.page_buffer[..4],
            &[bank as u8 + 1, bank as u8 + 1, bank as u8 + 1, 0]
        );
        assert_eq!(nand.spare_buffer, vec![0; NAND_BYTES_PER_SPARE]);
        select(&mut nand, bank, 1);
        assert_eq!(nand.page_buffer, vec![0; NAND_BYTES_PER_PAGE]);
        assert_eq!(
            nand.spare_buffer[0xa], 0,
            "empty present page is not missing"
        );
        select(&mut nand, bank, 2);
        assert_eq!(nand.page_buffer, vec![0; NAND_BYTES_PER_PAGE]);
        assert_eq!(nand.spare_buffer[0xa], 0xff);
        select(&mut nand, bank, u32::MAX);
        assert_eq!(nand.page_buffer, vec![bank as u8 + 17; NAND_BYTES_PER_PAGE]);
        assert_eq!(
            nand.spare_buffer,
            vec![bank as u8 + 17; NAND_BYTES_PER_SPARE]
        );
    }
}

#[test]
fn vfl_discovery_keeps_noncanonical_names_and_existing_cached_observations() {
    let f = Fixture::new();
    f.page(0, "00128.page", &context_page());
    f.page(0, "+256.page", &context_page());
    f.page(0, "384.page", &context_page());
    f.page(0, "385.page", &context_page());
    f.page(0, "512.page", &[0; 2057]); // truncated before spare type
    f.page(0, "640.PAGE", &context_page());
    f.page(0, "invalid.page", &context_page());
    let mut nand = f.controller();
    assert_eq!(nand.sparse_vfl_context_blocks(0), [1, 2, 3]);
    // An already cached scan remains stale exactly as the source controller is.
    f.page(0, "768.page", &context_page());
    let mut restored = roundtrip(&nand);
    assert_eq!(restored.sparse_vfl_context_blocks(0), [1, 2, 3]);
    restored.sparse_vfl_context_blocks[0] = None;
    assert_eq!(restored.sparse_vfl_context_blocks(0), [1, 2, 3, 6]);
    select(&mut restored, 0, 128);
    assert_eq!(restored.spare_buffer[0xa], 0xff, "00128.page is scan-only");
}

#[test]
fn partial_fifo_and_write_and_multibank_dma_resume_at_exact_cursor() {
    let f = Fixture::new();
    let data = (0..512u32).flat_map(u32::to_le_bytes).collect::<Vec<_>>();
    f.page(0, "17.page", &data);
    f.page(7, "19.page", &vec![0xa5; NAND_BYTES_PER_PAGE]);
    let mut nand = f.controller();
    nand.set_bank(0);
    nand.write(0xc, 17 << 16);
    nand.write(0x30, 2047);
    assert_eq!(nand.read(0x80), 0);
    assert_eq!(nand.read(0x80), 1);
    let mut restored = roundtrip(&nand);
    for word in 2..512 {
        assert_eq!(restored.read(0x80), word);
    }
    assert_eq!(restored.fmdnum, u32::MAX);
    assert_eq!(restored.read(0x80), 0, "exhausted FIFO is bounded");

    nand.begin_page_write(0, 17);
    nand.write(0x80, 0x12345678);
    let mut restored = roundtrip(&nand);
    assert!(restored.is_writing);
    assert_eq!(restored.fmdnum, 2044);
    restored.write(0x80, 0xabcdef01);
    assert_eq!(
        &restored.page_buffer[..8],
        &[0x78, 0x56, 0x34, 0x12, 1, 0xef, 0xcd, 0xab]
    );
    assert_eq!(
        nand.page_buffer[4..8],
        1u32.to_le_bytes(),
        "restored write is detached"
    );

    nand.reading_multiple_pages = true;
    nand.cur_bank_reading = -1;
    nand.banks_to_read[0] = 0;
    nand.pages_to_read[0] = 17;
    nand.banks_to_read[1] = 7;
    nand.pages_to_read[1] = 19;
    nand.fmdnum = 4096;
    assert_eq!(nand.read(0x80), 0x12345678);
    let mut restored = roundtrip(&nand);
    for word in 1..512 {
        assert_eq!(restored.read(0x80), word);
    }
    assert_eq!(restored.read(0x80), 0xa5a5a5a5);
    assert_eq!(restored.cur_bank_reading, 1);
    assert_eq!(restored.fmdnum, 2044);
}

#[test]
fn registers_spare_phase_all_dma_rows_and_kernel_stage_are_preserved() {
    let f = Fixture::new();
    let mut data = vec![0; NAND_BYTES_PER_PAGE];
    data.extend((0..16u32).flat_map(|word| (0x12340000 + word).to_le_bytes()));
    f.page(3, "65537.page", &data);
    let mut nand = f.controller();
    nand.set_bank(3);
    for (offset, value) in [
        (4, 0x123),
        (0xc, 1 << 16),
        (0x10, 1),
        (0x2c, 0xabcd),
        (0x100, 0x34),
    ] {
        nand.write(offset, value);
    }
    nand.write(0x30, 63);
    nand.set_kernel_started(true);
    for i in 0..512 {
        nand.banks_to_read[i] = (i % 8) as u32;
        nand.pages_to_read[i] = i as u32;
    }
    assert_eq!(nand.read(0x80), 0x12340000);
    let mut restored = roundtrip(&nand);
    assert!(restored.kernel_started && restored.reading_spare);
    for word in 1..16 {
        assert_eq!(restored.read(0x80), 0x12340000 + word);
    }
    assert_eq!(restored.fmctrl1, 0x123);
    assert_eq!(restored.fmanum, 0xabcd);
    assert_eq!(restored.rsctrl, 0x34);
    assert_eq!(restored.banks_to_read, nand.banks_to_read);
    assert_eq!(restored.pages_to_read, nand.pages_to_read);
}

#[test]
fn bitmap_limit_is_bounded_and_inclusive_at_byte_boundaries() {
    let f = Fixture::new();
    let mut bbt = vec![0; NAND_BYTES_PER_PAGE];
    bbt[..16].copy_from_slice(NAND_DEVICEINFO_BBT_MAGIC);
    f.page(0, "1.page", &bbt);
    for upto in [0, 6, 7, 8, 15, 16, 16255, 16256, u32::MAX] {
        let mut nand = f.controller();
        nand.policy.as_mut().unwrap().bbt_good_upto = Some(upto);
        nand.set_kernel_started(true);
        let mut restored = roundtrip(&nand);
        select(&mut restored, 0, 1);
        for (byte, &bits) in restored.page_buffer[16..].iter().enumerate() {
            let mut expected = 0u8;
            for bit in 0..8 {
                if byte as u64 * 8 + bit <= u64::from(upto) {
                    expected |= 1 << bit;
                }
            }
            assert_eq!(bits, expected, "upto={upto}, byte={byte}");
        }
    }
}

#[test]
fn strict_image_admission_rejects_truncation_trailing_tags_counts_and_shapes() {
    let f = Fixture::new();
    f.page(0, "0.page", &[1, 2, 3]);
    let nand = f.controller();
    let bytes = nand.capture_checkpoint(LIMIT).unwrap();
    for end in 0..bytes.len() {
        assert!(
            S5lNand::from_checkpoint(&bytes[..end], LIMIT).is_err(),
            "end={end}"
        );
    }
    let mut invalid = bytes.clone();
    invalid.push(0);
    assert!(S5lNand::from_checkpoint(&invalid, LIMIT).is_err());
    assert!(S5lNand::from_checkpoint(&bytes, bytes.len() - 1).is_err());
    for (offset, replacement) in [(0, 0), (40, 2)] {
        let mut invalid = bytes.clone();
        invalid[offset] = replacement;
        assert!(S5lNand::from_checkpoint(&invalid, LIMIT).is_err());
    }
    // Fixed header: 8 tag + 32 regs + 4 flags + 24 cursors + 2112 buffers
    // + 4096 DMA + 8 absent caches + 5 absent/false policy bytes = 6289.
    let count_offset = 8 + 32 + 4 + 24 + 2112 + 4096 + 8 + 5;
    let mut invalid = bytes.clone();
    invalid[count_offset..count_offset + 8].copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(S5lNand::from_checkpoint(&invalid, LIMIT).is_err());
    let page_offset = count_offset + 8;
    for (offset, value) in [(page_offset, 8), (page_offset + 8, 2113)] {
        let mut invalid = bytes.clone();
        invalid[offset..offset + 4].copy_from_slice(&u32::to_le_bytes(value));
        assert!(S5lNand::from_checkpoint(&invalid, LIMIT).is_err());
    }
    let mut malformed = f.controller();
    malformed.banks_to_read.pop();
    assert!(malformed.capture_checkpoint(LIMIT).is_err());
    assert_eq!(
        nand.capture_checkpoint(LIMIT).unwrap(),
        bytes,
        "rejections never mutate source"
    );
}

#[test]
fn capture_budget_failure_is_read_only_and_nonregular_media_is_rejected() {
    let f = Fixture::new();
    f.page(0, "1.page", &[0xa5; 2112]);
    let nand = f.controller();
    let bytes = nand.capture_checkpoint(LIMIT).unwrap();
    assert_eq!(nand.capture_checkpoint(bytes.len()).unwrap(), bytes);
    assert!(nand.capture_checkpoint(bytes.len() - 1).is_err());
    assert!(nand.capture_checkpoint(0).is_err());
    assert_eq!(nand.buffered_page, -1);
    assert!(nand.sparse_vfl_context_blocks.iter().all(Option::is_none));
    fs::create_dir(f.0.join("bank0/2.page")).unwrap();
    assert!(nand.capture_checkpoint(LIMIT).is_err());
    assert_eq!(nand.buffered_page, -1);
    assert!(nand.sparse_vfl_context_blocks.iter().all(Option::is_none));
}

fn policy_child(root: &Path, image: &Path, source: bool) {
    if source {
        let mut nand = S5lNand::new(Some(root.to_owned()));
        nand.set_kernel_started(true);
        fs::write(image, nand.capture_checkpoint(LIMIT).unwrap()).unwrap();
    } else {
        let mut nand = S5lNand::from_checkpoint(&fs::read(image).unwrap(), LIMIT).unwrap();
        select(&mut nand, 0, 1);
        assert_eq!(nand.page_buffer[16], 0xff);
        assert_eq!(nand.page_buffer[17], 0, "saved inclusive good_upto=7");
        select(&mut nand, 0, 2);
        assert_eq!(nand.page_buffer[450], 0xaf);
        assert_eq!(&nand.page_buffer[454..458], &123u32.to_le_bytes());
        assert_eq!(&nand.page_buffer[458..462], &456u32.to_le_bytes());
    }
}

#[test]
fn restored_policy_ignores_conflicting_environment_in_fresh_process() {
    const MARKER: &str = "RAX_NAND_POLICY_CHILD";
    if let Ok(mode) = std::env::var(MARKER) {
        policy_child(
            Path::new(&std::env::var("RAX_NAND_CHILD_ROOT").unwrap()),
            Path::new(&std::env::var("RAX_NAND_CHILD_IMAGE").unwrap()),
            mode == "source",
        );
        return;
    }
    let f = Fixture::new();
    let mut bbt = vec![0; 2048];
    bbt[..16].copy_from_slice(NAND_DEVICEINFO_BBT_MAGIC);
    f.page(0, "1.page", &bbt);
    let mut pmbr = vec![0; 2048];
    pmbr[510..512].copy_from_slice(&[0x55, 0xaa]);
    pmbr[450] = 0xee;
    pmbr[458..462].copy_from_slice(&1u32.to_le_bytes());
    f.page(0, "2.page", &pmbr);
    let image = f.0.join("checkpoint.bin");
    for source in [true, false] {
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command.args(["--exact", "devices::s5l8900::nand::checkpoint_tests::restored_policy_ignores_conflicting_environment_in_fresh_process", "--nocapture"])
            .env(MARKER, if source {"source"} else {"target"})
            .env("RAX_NAND_CHILD_ROOT", &f.0).env("RAX_NAND_CHILD_IMAGE", &image)
            .env("RAX_S5L_BBT_GOOD_UPTO", if source {"7"} else {"99"})
            .env("RAX_S5L_REWRITE_PMBR_AS_FDISK", "1")
            .env("RAX_S5L_FDISK_RELSECT", if source {"123"} else {"987"})
            .env("RAX_S5L_FDISK_NUMSECT", if source {"456"} else {"654"});
        if source {
            command.env_remove("RAX_S5L_BBT_ALL_GOOD");
        } else {
            command.env("RAX_S5L_BBT_ALL_GOOD", "1");
            fs::remove_dir_all(f.0.join("bank0")).unwrap();
        }
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "source={source}: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed"));
    }
}

#[test]
fn canonical_image_is_path_and_directory_order_independent_and_ignores_unobserved_tail() {
    let a = Fixture::new();
    let b = Fixture::new();
    for page in [2, 1, 0] {
        a.page(0, &format!("{page}.page"), &vec![page as u8; 4096]);
    }
    for page in [0, 1, 2] {
        let mut data = vec![page as u8; 2112];
        data.extend_from_slice(&[0xee; 1024]);
        b.page(0, &format!("{page}.page"), &data);
    }
    assert_eq!(
        a.controller().capture_checkpoint(LIMIT).unwrap(),
        b.controller().capture_checkpoint(LIMIT).unwrap()
    );
}

#[test]
fn restored_extreme_cursors_remain_safe_and_image_errors_leave_existing_owner_unchanged() {
    let f = Fixture::new();
    let mut nand = f.controller();
    nand.reading_multiple_pages = true;
    nand.cur_bank_reading = i64::MAX;
    nand.banks_to_read[511] = u32::MAX;
    nand.fmdnum = 0;
    let mut restored = roundtrip(&nand);
    assert_eq!(restored.read(0x80), 0);
    assert_eq!(restored.cur_bank_reading, i64::MAX);
    assert_eq!(restored.fmdnum, u32::MAX - 3);
    let before = nand.capture_checkpoint(LIMIT).unwrap();
    let mut invalid = before.clone();
    invalid[44..52].copy_from_slice(&8i64.to_le_bytes());
    assert!(S5lNand::from_checkpoint(&invalid, LIMIT).is_err());
    invalid = before.clone();
    invalid[60..68].copy_from_slice(&(-2i64).to_le_bytes());
    assert!(S5lNand::from_checkpoint(&invalid, LIMIT).is_err());
    assert_eq!(nand.capture_checkpoint(LIMIT).unwrap(), before);
}

#[test]
fn cache_block_and_media_order_counts_are_admitted_before_allocation() {
    let f = Fixture::new();
    let mut nand = f.controller();
    nand.sparse_vfl_context_blocks[0] = Some(vec![1, 3]);
    let bytes = nand.capture_checkpoint(LIMIT).unwrap();
    // First cache: fixed prefix 6276 bytes, then Some byte, count, words.
    let cache = 8 + 32 + 4 + 24 + 2112 + 4096;
    for count in [33554433u32, u32::MAX] {
        let mut invalid = bytes.clone();
        invalid[cache + 1..cache + 5].copy_from_slice(&count.to_le_bytes());
        assert!(S5lNand::from_checkpoint(&invalid, LIMIT).is_err());
    }
    for values in [[1u32, 1], [3, 1], [1, 33554432]] {
        let mut invalid = bytes.clone();
        invalid[cache + 5..cache + 9].copy_from_slice(&values[0].to_le_bytes());
        invalid[cache + 9..cache + 13].copy_from_slice(&values[1].to_le_bytes());
        assert!(S5lNand::from_checkpoint(&invalid, LIMIT).is_err());
    }
    f.page(0, "0.page", &[]);
    f.page(0, "1.page", &[]);
    nand.sparse_vfl_context_blocks[0] = None;
    let bytes = nand.capture_checkpoint(LIMIT).unwrap();
    let count = cache + 8 + 5;
    let first = count + 8;
    let second = first + 12;
    for (offset, value) in [(second + 4, 0u32), (first, 8)] {
        let mut invalid = bytes.clone();
        invalid[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        assert!(S5lNand::from_checkpoint(&invalid, LIMIT).is_err());
    }
}

#[test]
fn exact_budget_charges_unique_vfl_blocks_before_admission() {
    let f = Fixture::new();
    let data = context_page();
    for page in 0..128 {
        f.page(0, &format!("{page}.page"), &data);
    }
    let nand = f.controller();
    let bytes = nand.capture_checkpoint(LIMIT).unwrap();
    assert_eq!(bytes.len(), 278205);
    let restored = S5lNand::from_checkpoint(&bytes, bytes.len()).unwrap();
    assert_eq!(restored.capture_checkpoint(bytes.len()).unwrap(), bytes);
    assert_eq!(nand.capture_checkpoint(bytes.len()).unwrap(), bytes);
    // Numeric aliases only repeat the existing block observation. They do not
    // add page records or consume extra encoded-media budget.
    for width in 2..82 {
        f.page(0, &format!("{:0width$}.page", 0), &data);
    }
    assert_eq!(nand.capture_checkpoint(bytes.len()).unwrap(), bytes);
    assert!(nand.capture_checkpoint(bytes.len() - 1).is_err());
    assert!(nand.sparse_vfl_context_blocks.iter().all(Option::is_none));
}
