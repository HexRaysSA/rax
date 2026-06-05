//! El-Torito (BIOS CD) boot support for legacy/real-mode boot — e.g. TempleOS.
//!
//! rax's Linux path loads an ELF kernel straight into long mode. An El-Torito
//! bootable ISO instead expects the BIOS to load a "no-emulation" boot image at
//! `0x7C00` and start it in 16-bit real mode (`CS:IP = 0:0x7C00`, `DL` = boot
//! drive). This module parses the El-Torito boot catalog and extracts the boot
//! image + real-mode entry parameters; the VM then runs it in real mode with a
//! minimal BIOS (INT 10h/13h) servicing the bootloader's requests.

/// CD-ROM logical sector size (ISO-9660 / El-Torito LBAs are in these units).
pub const CD_SECTOR: usize = 2048;

/// Parsed El-Torito initial (default) boot entry plus the extracted boot image.
#[derive(Debug, Clone)]
pub struct ElToritoBoot {
    /// Media emulation type: 0 = no emulation (the only mode we support).
    pub media_type: u8,
    /// Real-mode load segment. A catalog value of 0 means the BIOS default
    /// `0x07C0`, i.e. load at linear `0x7C00`.
    pub load_segment: u16,
    /// Linear load address (`load_segment << 4`).
    pub load_addr: u32,
    /// Number of 512-byte virtual sectors the BIOS loads from the image.
    pub sector_count: u16,
    /// CD LBA (2048-byte sectors) of the boot image within the ISO.
    pub image_lba: u32,
    /// The boot image bytes (`sector_count * 512`), to be placed at `load_addr`.
    pub boot_image: Vec<u8>,
}

/// Parse the El-Torito boot catalog of an ISO-9660 image and extract the
/// initial (default) no-emulation boot image.
pub fn parse_el_torito(iso: &[u8]) -> Result<ElToritoBoot, String> {
    // Boot Record Volume Descriptor lives at ISO sector 17 (offset 0x8800):
    //   [0]      = descriptor type 0 (boot record)
    //   [1..6]   = "CD001"
    //   [6]      = version 1
    //   [7..0x1F]= "EL TORITO SPECIFICATION"
    //   [0x47..] = absolute pointer (LE u32) to the boot catalog sector.
    let brvd = 17 * CD_SECTOR;
    if iso.len() < brvd + 0x4B {
        return Err("ISO too small for an El-Torito boot record".into());
    }
    if &iso[brvd + 1..brvd + 6] != b"CD001" {
        return Err("no CD001 at sector 17 (not a boot-record volume descriptor)".into());
    }
    if &iso[brvd + 7..brvd + 7 + 23] != b"EL TORITO SPECIFICATION" {
        return Err("sector 17 is not an El-Torito boot record".into());
    }
    let cat_sector = u32::from_le_bytes(iso[brvd + 0x47..brvd + 0x4B].try_into().unwrap());
    let cat = cat_sector as usize * CD_SECTOR;
    if iso.len() < cat + 64 {
        return Err("El-Torito boot catalog is out of range".into());
    }

    // Validation entry (first 32 bytes): [0]=header id 1, [0x1E..0x20]=0x55 0xAA.
    if iso[cat] != 0x01 {
        return Err(format!("bad El-Torito validation header id 0x{:02x}", iso[cat]));
    }
    if iso[cat + 0x1E] != 0x55 || iso[cat + 0x1F] != 0xAA {
        return Err("bad El-Torito validation entry signature (0x55AA)".into());
    }

    // Initial/default entry at catalog + 32 (32 bytes):
    //   [0]      = boot indicator (0x88 = bootable)
    //   [1]      = media type (0 = no emulation)
    //   [2..4]   = load segment (LE, 0 => default 0x07C0)
    //   [6..8]   = sector count (LE, 512-byte virtual sectors)
    //   [8..12]  = image LBA (LE, 2048-byte CD sectors)
    let e = cat + 32;
    if iso[e] != 0x88 {
        return Err(format!("initial boot entry not bootable (0x{:02x})", iso[e]));
    }
    let media_type = iso[e + 1];
    let raw_seg = u16::from_le_bytes([iso[e + 2], iso[e + 3]]);
    let load_segment = if raw_seg == 0 { 0x07C0 } else { raw_seg };
    let sector_count = u16::from_le_bytes([iso[e + 6], iso[e + 7]]);
    let image_lba = u32::from_le_bytes(iso[e + 8..e + 12].try_into().unwrap());
    let load_addr = (load_segment as u32) << 4;

    let img_off = image_lba as usize * CD_SECTOR;
    let img_len = sector_count as usize * 512;
    if iso.len() < img_off + img_len {
        return Err("El-Torito boot image is out of range".into());
    }
    let boot_image = iso[img_off..img_off + img_len].to_vec();

    Ok(ElToritoBoot {
        media_type,
        load_segment,
        load_addr,
        sector_count,
        image_lba,
        boot_image,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal in-memory ISO carrying an El-Torito no-emulation boot
    /// entry that mirrors TempleOS's catalog, and check the parser recovers it.
    #[test]
    fn parse_no_emulation_boot_image() {
        let cat_sector = 0x14u32; // boot catalog at LBA 0x14
        let image_lba = 0x15u32; // boot image at LBA 0x15
        let sector_count = 4u16; // 4 * 512 = 2048 bytes
        let mut iso = vec![0u8; (image_lba as usize + 1) * CD_SECTOR];

        // Boot Record Volume Descriptor at sector 17.
        let brvd = 17 * CD_SECTOR;
        iso[brvd] = 0; // boot record
        iso[brvd + 1..brvd + 6].copy_from_slice(b"CD001");
        iso[brvd + 6] = 1;
        iso[brvd + 7..brvd + 7 + 23].copy_from_slice(b"EL TORITO SPECIFICATION");
        iso[brvd + 0x47..brvd + 0x4B].copy_from_slice(&cat_sector.to_le_bytes());

        // Boot catalog: validation entry + initial entry.
        let cat = cat_sector as usize * CD_SECTOR;
        iso[cat] = 0x01;
        iso[cat + 0x1E] = 0x55;
        iso[cat + 0x1F] = 0xAA;
        let e = cat + 32;
        iso[e] = 0x88; // bootable
        iso[e + 1] = 0x00; // no emulation
        iso[e + 2..e + 4].copy_from_slice(&0u16.to_le_bytes()); // load seg 0 => 0x7C0
        iso[e + 6..e + 8].copy_from_slice(&sector_count.to_le_bytes());
        iso[e + 8..e + 12].copy_from_slice(&image_lba.to_le_bytes());

        // Boot image: a recognizable marker at its start (TempleOS starts `fc b8`).
        let img = image_lba as usize * CD_SECTOR;
        iso[img] = 0xFC; // cld
        iso[img + 1] = 0xB8; // mov ax, imm16

        let boot = parse_el_torito(&iso).expect("parse El-Torito");
        assert_eq!(boot.media_type, 0);
        assert_eq!(boot.load_segment, 0x07C0);
        assert_eq!(boot.load_addr, 0x7C00);
        assert_eq!(boot.sector_count, 4);
        assert_eq!(boot.image_lba, 0x15);
        assert_eq!(boot.boot_image.len(), 2048);
        assert_eq!(&boot.boot_image[..2], &[0xFC, 0xB8]);
    }

    #[test]
    fn rejects_non_boot_iso() {
        let iso = vec![0u8; 20 * CD_SECTOR];
        assert!(parse_el_torito(&iso).is_err());
    }
}
