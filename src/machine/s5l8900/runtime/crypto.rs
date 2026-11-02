//! S5L8900 boot-image and AES-engine crypto services.

use super::*;

impl S5L8900Vcpu {
    /// Service an 8900-engine in-place AES-CBC decryption request. `addr` is
    /// the physical address of the 8900 image header; the body that follows
    /// is decrypted in place. This mirrors the devos50 QEMU reference hook for
    /// the missing fused bootrom decrypt routine at 0x22000000.
    pub(super) fn decrypt_8900(&mut self, addr: u32) {
        info!(
            addr = format!("{addr:#x}"),
            len = S5L_8900_HEADER_LEN,
            "Reading 8900 header"
        );

        let mut header = [0u8; S5L_8900_HEADER_LEN];
        if self
            .bridge
            .mem
            .read_slice(&mut header, GuestAddress(addr as u64))
            .is_err()
        {
            debug!(addr = format!("{addr:#x}"), "8900 header read failed");
            return;
        }

        if &header[..4] != b"8900" {
            info!(addr = format!("{addr:#x}"), "Bad 8900 magic");
            return;
        }

        let encrypted = header[7];
        let data_len = u32::from_le_bytes(header[12..16].try_into().unwrap()) as usize;
        info!(
            addr = format!("{addr:#x}"),
            len = data_len,
            encrypted = format!("{encrypted:#x}"),
            "Will decrypt 8900 image"
        );

        if encrypted != 0x03 {
            return;
        }
        if data_len == 0 || data_len % 16 != 0 {
            debug!(len = data_len, "invalid 8900 data length");
            return;
        }

        let Some(body_addr) = addr.checked_add(S5L_8900_HEADER_LEN as u32) else {
            return;
        };
        // Bound the guest-controlled data_len against actual guest RAM before
        // allocating. The length comes from the guest-supplied 8900 header, so an
        // unbounded `vec![0u8; data_len]` could be forced to multi-GB (host
        // OOM/DoS) before `read_slice` ever rejects an out-of-range body. (issue #50)
        let (mem_start, mem_end) =
            dma_ram_bounds_from_mmap_end(self.bridge.mem.last_addr().raw_value().saturating_add(1));
        if !dma_range_in_bounds(mem_start, mem_end, body_addr, data_len) {
            debug!(len = data_len, "8900 data length exceeds guest memory");
            return;
        }
        let mut body = vec![0u8; data_len];
        if self
            .bridge
            .mem
            .read_slice(&mut body, GuestAddress(body_addr as u64))
            .is_err()
        {
            debug!(
                addr = format!("{body_addr:#x}"),
                len = data_len,
                "8900 body read failed"
            );
            return;
        }

        if let Some(key) = AesKey::new(&S5L_8900_IMAGE_KEY) {
            let iv = [0u8; 16];
            aes_cbc_decrypt(&key, &iv, &mut body);
            let _ = self
                .bridge
                .mem
                .write_slice(&body, GuestAddress(body_addr as u64));
            if let Ok(path) = std::env::var("RAX_S5L_DUMP_8900") {
                if std::fs::write(&path, &body).is_ok() {
                    info!(path, len = body.len(), "dumped decrypted 8900 body");
                }
            }
        }
    }

    /// Service an AES-engine `AES_GO`: DMA `insize` bytes from `inaddr`, AES-CBC
    /// decrypt them with the selected key, and write the plaintext to `outaddr`
    /// (in guest physical memory). The GID key, which is not in the QEMU
    /// reference, may be supplied as 16/24/32 hex bytes via `RAX_S5L_GID_KEY`.
    pub(super) fn service_aes(&mut self) {
        let (inaddr, outaddr, insize, keytype, custkey, ivec) = {
            let inner = self.bridge.inner.borrow();
            let a = &inner.aes;
            (a.inaddr, a.outaddr, a.insize, a.keytype, a.custkey, a.ivec)
        };

        // Resolve the decryption key.
        let key_bytes: Option<Vec<u8>> = match keytype {
            AesKeyType::Uid => Some(AES_UID_KEY.to_vec()),
            AesKeyType::Custom => {
                // Custom key length follows the AES key-length register; default
                // to AES-256 (the engine's widest) using all 32 bytes.
                Some(custkey.to_vec())
            }
            AesKeyType::Gid => self.effective_guest_profile().gid_key.clone(),
        };

        let len = insize as usize;
        let mut ok = false;
        // Bound the guest-controlled AES size against actual guest RAM before
        // allocating. `insize` comes straight from a guest MMIO register, so an
        // unbounded `vec![0u8; len]` could be forced up to ~4 GiB (host OOM/DoS)
        // before `read_slice` ever validates the source range. Require both the
        // source (`inaddr`) and destination (`outaddr`) DMA ranges to fit in
        // guest memory. (issue #43)
        let (mem_start, mem_end) =
            dma_ram_bounds_from_mmap_end(self.bridge.mem.last_addr().raw_value().saturating_add(1));
        let in_bounds = dma_range_in_bounds(mem_start, mem_end, inaddr, len)
            && dma_range_in_bounds(mem_start, mem_end, outaddr, len);
        if let Some(kb) = key_bytes {
            if let Some(key) = AesKey::new(&kb) {
                if len > 0 && len % 16 == 0 && in_bounds {
                    let mut buf = vec![0u8; len];
                    if self
                        .bridge
                        .mem
                        .read_slice(&mut buf, GuestAddress(inaddr as u64))
                        .is_ok()
                    {
                        aes_cbc_decrypt(&key, &ivec, &mut buf);
                        ok = self
                            .bridge
                            .mem
                            .write_slice(&buf, GuestAddress(outaddr as u64))
                            .is_ok();
                    }
                }
            }
        }

        if self.fault_log_budget > 0 {
            self.fault_log_budget -= 1;
            debug!(
                inaddr = format!("{inaddr:#x}"),
                outaddr = format!("{outaddr:#x}"),
                insize = len,
                keytype = match keytype {
                    AesKeyType::Uid => "uid",
                    AesKeyType::Gid => "gid",
                    AesKeyType::Custom => "custom",
                },
                ok,
                "aes engine decrypt"
            );
        }

        let mut inner = self.bridge.inner.borrow_mut();
        inner.aes.pending_go = false;
        inner.aes.outsize = insize;
        inner.aes.finish();
    }

    /// Compute the SHA-1 digest of a guest physical region (for the SHA engine
    /// / image-hash verification path). Returns the 20-byte digest.
    #[allow(dead_code)]
    pub(super) fn sha1_region(&self, addr: u32, len: u32) -> Option<[u8; 20]> {
        let mut buf = vec![0u8; len as usize];
        self.bridge
            .mem
            .read_slice(&mut buf, GuestAddress(addr as u64))
            .ok()?;
        Some(sha1(&buf))
    }
}
