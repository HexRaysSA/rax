//! S5L platform storage trace.
use super::*;

impl S5L8900Vcpu {
    pub(super) fn trace_storage_call(&mut self, pc: u32) {
        if self.storage_call_trace_remaining == 0
            || self.insn_count < self.storage_call_trace_start_insn
        {
            return;
        }

        let lr = self.cpu.regs[14];
        if !(0xc045_b000..0xc045_d1a8).contains(&pc)
            || !(0xc044_a000..0xc045_5e40).contains(&(lr & !1))
        {
            return;
        }

        let key = (pc, lr);
        if self.storage_call_trace_seen.contains(&key) {
            return;
        }
        self.storage_call_trace_seen.push(key);
        self.storage_call_trace_remaining -= 1;

        info!(
            pc = format!("{pc:#x}"),
            lr = format!("{lr:#x}"),
            r0 = format!("{:#x}", self.cpu.regs[0]),
            r1 = format!("{:#x}", self.cpu.regs[1]),
            r2 = format!("{:#x}", self.cpu.regs[2]),
            r3 = format!("{:#x}", self.cpu.regs[3]),
            r0_words = self.guest_word_window(self.cpu.regs[0], 6),
            r1_words = self.guest_word_window(self.cpu.regs[1], 4),
            r2_words = self.guest_word_window(self.cpu.regs[2], 4),
            insns = self.insn_count,
            "storage call trace"
        );
    }

    pub(super) fn trace_fdisk_partition(&mut self, pc: u32) {
        if self.fdisk_trace_remaining == 0 {
            return;
        }

        let Some((_, reason)) = KERNEL_FDISK_TRACE_PCS
            .iter()
            .find(|(trace_pc, _)| *trace_pc == pc)
        else {
            return;
        };

        let lr = self.cpu.regs[14];
        let key = (pc, lr & !1);
        if self.fdisk_trace_seen.contains(&key) {
            return;
        }
        self.fdisk_trace_seen.push(key);
        self.fdisk_trace_remaining -= 1;

        let r0_vtable = self.bridge.read_word(self.cpu.regs[0]).unwrap_or(0);
        let r1_vtable = self.bridge.read_word(self.cpu.regs[1]).unwrap_or(0);
        let r2_vtable = self.bridge.read_word(self.cpu.regs[2]).unwrap_or(0);
        let r3_vtable = self.bridge.read_word(self.cpu.regs[3]).unwrap_or(0);
        let sp = self.cpu.regs[13];

        info!(
            pc = format!("{pc:#x}"),
            reason,
            r0 = format!("{:#x}", self.cpu.regs[0]),
            r1 = format!("{:#x}", self.cpu.regs[1]),
            r2 = format!("{:#x}", self.cpu.regs[2]),
            r3 = format!("{:#x}", self.cpu.regs[3]),
            r4 = format!("{:#x}", self.cpu.regs[4]),
            r5 = format!("{:#x}", self.cpu.regs[5]),
            r6 = format!("{:#x}", self.cpu.regs[6]),
            r7 = format!("{:#x}", self.cpu.regs[7]),
            r8 = format!("{:#x}", self.cpu.regs[8]),
            r9 = format!("{:#x}", self.cpu.regs[9]),
            r10 = format!("{:#x}", self.cpu.regs[10]),
            r11 = format!("{:#x}", self.cpu.regs[11]),
            r12 = format!("{:#x}", self.cpu.regs[12]),
            sp = format!("{sp:#x}"),
            lr = format!("{lr:#x}"),
            r0_str = ?self.guest_cstr(self.cpu.regs[0], 128),
            r1_str = ?self.guest_cstr(self.cpu.regs[1], 128),
            r2_str = ?self.guest_cstr(self.cpu.regs[2], 128),
            r3_str = ?self.guest_cstr(self.cpu.regs[3], 128),
            r0_vtable = format!("{r0_vtable:#x}"),
            r1_vtable = format!("{r1_vtable:#x}"),
            r2_vtable = format!("{r2_vtable:#x}"),
            r3_vtable = format!("{r3_vtable:#x}"),
            r0_words = self.guest_word_window(self.cpu.regs[0], 16),
            r1_words = self.guest_word_window(self.cpu.regs[1], 16),
            r2_words = self.guest_word_window(self.cpu.regs[2], 16),
            r3_words = self.guest_word_window(self.cpu.regs[3], 16),
            r4_words = self.guest_word_window(self.cpu.regs[4], 16),
            r5_words = self.guest_word_window(self.cpu.regs[5], 16),
            r6_words = self.guest_word_window(self.cpu.regs[6], 16),
            sp_words = self.guest_word_window(sp, 20),
            stack_refs = self.stack_code_refs(sp, 128),
            trail = self.recent_pc_trail(32),
            insns = self.insn_count,
            "fdisk partition trace"
        );
    }

    pub(super) fn trace_nandftl_start(&mut self, pc: u32) {
        if self.nandftl_trace_remaining == 0 {
            return;
        }

        let Some((_, reason)) = KERNEL_NANDFTL_TRACE_PCS
            .iter()
            .find(|(trace_pc, _)| *trace_pc == pc)
        else {
            return;
        };

        let lr = self.cpu.regs[14];
        let key = (pc, lr & !1);
        if self.nandftl_trace_seen.contains(&key) {
            return;
        }
        self.nandftl_trace_seen.push(key);
        self.nandftl_trace_remaining -= 1;

        let sp = self.cpu.regs[13];
        let r0_vtable = self.bridge.read_word(self.cpu.regs[0]).unwrap_or(0);
        let r4_vtable = self.bridge.read_word(self.cpu.regs[4]).unwrap_or(0);
        let r5_vtable = self.bridge.read_word(self.cpu.regs[5]).unwrap_or(0);
        let r6_vtable = self.bridge.read_word(self.cpu.regs[6]).unwrap_or(0);
        let r6_block_device = self
            .bridge
            .read_word(self.cpu.regs[6].wrapping_add(0x54))
            .unwrap_or(0);
        let r6_workloop = self
            .bridge
            .read_word(self.cpu.regs[6].wrapping_add(0x8c))
            .unwrap_or(0);
        let r6_command_gate = self
            .bridge
            .read_word(self.cpu.regs[6].wrapping_add(0x94))
            .unwrap_or(0);

        info!(
            pc = format!("{pc:#x}"),
            reason,
            r0 = format!("{:#x}", self.cpu.regs[0]),
            r1 = format!("{:#x}", self.cpu.regs[1]),
            r2 = format!("{:#x}", self.cpu.regs[2]),
            r3 = format!("{:#x}", self.cpu.regs[3]),
            r4 = format!("{:#x}", self.cpu.regs[4]),
            r5 = format!("{:#x}", self.cpu.regs[5]),
            r6 = format!("{:#x}", self.cpu.regs[6]),
            r7 = format!("{:#x}", self.cpu.regs[7]),
            r8 = format!("{:#x}", self.cpu.regs[8]),
            r9 = format!("{:#x}", self.cpu.regs[9]),
            r10 = format!("{:#x}", self.cpu.regs[10]),
            r11 = format!("{:#x}", self.cpu.regs[11]),
            r12 = format!("{:#x}", self.cpu.regs[12]),
            sp = format!("{sp:#x}"),
            lr = format!("{lr:#x}"),
            r0_vtable = format!("{r0_vtable:#x}"),
            r4_vtable = format!("{r4_vtable:#x}"),
            r5_vtable = format!("{r5_vtable:#x}"),
            r6_vtable = format!("{r6_vtable:#x}"),
            r6_block_device = format!("{r6_block_device:#x}"),
            r6_workloop = format!("{r6_workloop:#x}"),
            r6_command_gate = format!("{r6_command_gate:#x}"),
            r0_words = self.guest_word_window(self.cpu.regs[0], 12),
            r4_words = self.guest_word_window(self.cpu.regs[4], 16),
            r5_words = self.guest_word_window(self.cpu.regs[5], 16),
            r6_words = self.guest_word_window(self.cpu.regs[6], 48),
            r6_state_words = self.guest_word_window(self.cpu.regs[6].wrapping_add(0x50), 24),
            block_device_words = self.guest_word_window(r6_block_device, 16),
            workloop_words = self.guest_word_window(r6_workloop, 12),
            command_gate_words = self.guest_word_window(r6_command_gate, 12),
            sp_words = self.guest_word_window(sp, 24),
            stack_refs = self.stack_code_refs(sp, 160),
            trail = self.recent_pc_trail(40),
            insns = self.insn_count,
            "nandftl start trace"
        );
    }

    pub(super) fn trace_wmr_init(&mut self, pc: u32) {
        if self.wmr_trace_remaining == 0 {
            return;
        }

        let Some((_, reason)) = KERNEL_WMR_TRACE_PCS
            .iter()
            .find(|(trace_pc, _)| *trace_pc == pc)
        else {
            return;
        };

        let sp = self.cpu.regs[13];
        let lr = self.cpu.regs[14];
        let loop_index = self
            .bridge
            .read_word(sp.wrapping_add(0x24))
            .unwrap_or(self.cpu.regs[4]);
        let dedup_tag = match pc {
            0xC046_3BBC..=0xC046_3CB8 => loop_index,
            _ => lr & !1,
        };
        let key = (pc, dedup_tag);
        if self.wmr_trace_seen.contains(&key) {
            return;
        }
        self.wmr_trace_seen.push(key);
        self.wmr_trace_remaining -= 1;

        let func_tbl = self.bridge.read_word(sp.wrapping_add(0x14)).unwrap_or(0);
        let buf_desc = self.bridge.read_word(sp.wrapping_add(0x0c)).unwrap_or(0);
        let status = self.bridge.read_word(sp.wrapping_add(0x10)).unwrap_or(0);
        let unit_sig = self.bridge.read_word(sp.wrapping_add(0x18)).unwrap_or(0);
        let sig_found = self.bridge.read_word(sp.wrapping_add(0x1c)).unwrap_or(0);
        let blk0_clean = self.bridge.read_word(sp.wrapping_add(0x20)).unwrap_or(0);
        let func_read = self
            .bridge
            .read_word(func_tbl.wrapping_add(0x04))
            .unwrap_or(0);
        let func_read_sig = self
            .bridge
            .read_word(func_tbl.wrapping_add(0x14))
            .unwrap_or(0);
        let func_notify = self
            .bridge
            .read_word(func_tbl.wrapping_add(0x28))
            .unwrap_or(0);
        let buf_main = self.bridge.read_word(buf_desc).unwrap_or(0);
        let buf_spare = self
            .bridge
            .read_word(buf_desc.wrapping_add(0x04))
            .unwrap_or(0);
        let buf_state = self
            .bridge
            .read_word(buf_desc.wrapping_add(0x08))
            .unwrap_or(0);
        let cs_count = self
            .bridge
            .read_halfword(self.cpu.regs[6].wrapping_add(0x0c))
            .unwrap_or(0);

        info!(
            pc = format!("{pc:#x}"),
            reason,
            r0 = format!("{:#x}", self.cpu.regs[0]),
            r1 = format!("{:#x}", self.cpu.regs[1]),
            r2 = format!("{:#x}", self.cpu.regs[2]),
            r3 = format!("{:#x}", self.cpu.regs[3]),
            r4 = format!("{:#x}", self.cpu.regs[4]),
            r5 = format!("{:#x}", self.cpu.regs[5]),
            r6 = format!("{:#x}", self.cpu.regs[6]),
            r7 = format!("{:#x}", self.cpu.regs[7]),
            r8 = format!("{:#x}", self.cpu.regs[8]),
            r9 = format!("{:#x}", self.cpu.regs[9]),
            r10 = format!("{:#x}", self.cpu.regs[10]),
            r11 = format!("{:#x}", self.cpu.regs[11]),
            r12 = format!("{:#x}", self.cpu.regs[12]),
            sp = format!("{sp:#x}"),
            lr = format!("{lr:#x}"),
            func_tbl = format!("{func_tbl:#x}"),
            func_read = format!("{func_read:#x}"),
            func_read_sig = format!("{func_read_sig:#x}"),
            func_notify = format!("{func_notify:#x}"),
            buf_desc = format!("{buf_desc:#x}"),
            buf_main = format!("{buf_main:#x}"),
            buf_spare = format!("{buf_spare:#x}"),
            buf_state = format!("{buf_state:#x}"),
            status = format!("{status:#x}"),
            unit_sig = format!("{unit_sig:#x}"),
            sig_found = format!("{sig_found:#x}"),
            blk0_clean = format!("{blk0_clean:#x}"),
            loop_index = format!("{loop_index:#x}"),
            cs_count = cs_count,
            r0_words = self.guest_word_window(self.cpu.regs[0], 8),
            r1_words = self.guest_word_window(self.cpu.regs[1], 8),
            r2_words = self.guest_word_window(self.cpu.regs[2], 8),
            r3_words = self.guest_word_window(self.cpu.regs[3], 8),
            wmr_global_words = self.guest_word_window(self.cpu.regs[6], 24),
            func_tbl_words = self.guest_word_window(func_tbl, 12),
            buf_desc_words = self.guest_word_window(buf_desc, 6),
            buf_main_words = self.guest_word_window(buf_main, 8),
            sp_words = self.guest_word_window(sp, 16),
            stack_refs = self.stack_code_refs(sp, 96),
            trail = self.recent_pc_trail(36),
            insns = self.insn_count,
            "wmr init trace"
        );
    }

    pub(super) fn track_wmr_init(&mut self, pc: u32) {
        match pc {
            0xC046_3AC8 => self.wmr_init_active = true,
            0xC046_3FB0 | 0xC046_3FB8 | 0xC046_3FC0 | 0xC046_3FC4 => {
                self.wmr_init_active = false;
            }
            _ => {}
        }
    }

    pub(super) fn trace_partition_scan(&mut self, pc: u32) {
        if self.partition_trace_remaining == 0 {
            return;
        }

        let gpt_reason = match pc {
            0xc044_ffc8 => Some("gpt probe before scan"),
            0xc044_ffce => Some("gpt probe scan returned"),
            0xc044_ffd0 => Some("gpt probe stored partitions"),
            0xc044_ffd4 => Some("gpt probe success"),
            0xc044_ffd8 => Some("gpt probe failure"),
            0xc044_ffda => Some("gpt probe return"),
            0xc044_ffe0 => Some("gpt start entry"),
            0xc044_fff0 => Some("gpt start super result"),
            0xc044_fffa => Some("gpt start iterator result"),
            0xc045_0036 => Some("gpt start next partition result"),
            0xc045_0042 => Some("gpt start success"),
            0xc045_0046 => Some("gpt start failure"),
            0xc045_01fc => Some("gpt protective mbr signature mismatch"),
            0xc045_0216 => Some("gpt multiple protective mbr entries"),
            0xc045_0226 => Some("gpt missing protective mbr entry"),
            0xc045_024a => Some("gpt header read failed"),
            0xc045_0274 => Some("gpt header signature mismatch"),
            0xc045_02a6 => Some("gpt header size too small"),
            0xc045_02ce => Some("gpt header crc mismatch"),
            0xc045_036e => Some("gpt entry size too small"),
            0xc045_03ba if self.cpu.regs[0] == 0 => Some("gpt entry buffer allocation failed"),
            0xc045_03e2 if self.cpu.regs[0] != 0 => Some("gpt entry table read failed"),
            0xc045_0406 => Some("gpt entry loop"),
            0xc045_0436 => Some("gpt isPartitionUsed result"),
            0xc045_044c => Some("gpt isPartitionCorrupt result"),
            0xc045_044e if self.cpu.regs[0] != 0 => Some("gpt partition corrupt"),
            0xc045_0462 => Some("gpt isPartitionInvalid result"),
            0xc045_0464 if self.cpu.regs[0] != 0 => Some("gpt partition invalid"),
            0xc045_0478 => Some("gpt instantiateMediaObject result"),
            0xc045_048a => Some("gpt setObject result"),
            0xc045_0492 => Some("gpt entry skipped"),
            0xc045_04b8 => Some("gpt scan success"),
            0xc045_04ba => Some("gpt scan error exit"),
            0xc045_051c => Some("gpt scan return value"),
            _ => None,
        };
        if pc == 0xc044_ffda && self.cpu.regs[0] != 0 {
            self.iokit_match_follow_remaining = 160;
        }

        let iokit_match_reason = match pc {
            0xc012_5c84 => Some("osordered setObject index entry"),
            0xc012_5cd6 => Some("osordered setObject index store"),
            0xc012_5cea => Some("osordered setObject index count update"),
            0xc012_5d34 => Some("osordered setObject entry"),
            0xc012_5d5a => Some("osordered comparator result"),
            0xc012_5d5c => Some("osordered comparator branch"),
            0xc012_5d66 => Some("osordered insert index chosen"),
            0xc012_5d72 => Some("osordered insert call"),
            0xc012_5f28 => Some("osordered getNext entry"),
            0xc012_5f3c => Some("osordered getNext load item"),
            0xc013_6c42 => Some("iokit start categories entry"),
            0xc013_6c5a => Some("iokit start category iterator valid"),
            0xc013_6c6a => Some("iokit start lookup category list"),
            0xc013_6c76 => Some("iokit start category list result"),
            0xc013_6ca4 => Some("iokit start candidate result"),
            0xc013_6ca6 => Some("iokit start category empty"),
            0xc013_6cbe => Some("iokit start candidate before table"),
            0xc013_6ce0 => Some("iokit start candidate debug"),
            0xc013_6d18 => Some("iokit startCandidate call"),
            0xc013_6d28 => Some("iokit startCandidate returned"),
            0xc013_6d2c => Some("iokit startCandidate failed log"),
            0xc013_6d60 => Some("iokit start match category skip"),
            0xc013_6dd0 => Some("iokit start categories done"),
            0xc013_7082 => Some("iokit match probe returned"),
            0xc013_7092 => Some("iokit match after detach"),
            0xc013_7094 => Some("iokit match test probe result"),
            0xc013_7096 => Some("iokit match branch on probe result"),
            0xc013_70c0 => Some("iokit match current best check"),
            0xc013_70c6 => Some("iokit match start best service"),
            0xc013_70d2 => Some("iokit match start best returned"),
            0xc013_70d6 => Some("iokit match best start null"),
            0xc013_70e0 => Some("iokit match notify probe winner"),
            0xc013_70e2 => Some("iokit match notify returned"),
            0xc013_711e => Some("iokit match no probe result"),
            0xc013_7138 => Some("iokit match candidate cleanup"),
            0xc013_7162 => Some("iokit match start failed path"),
            0xc013_71a2 => Some("iokit match no current best"),
            _ => None,
        };

        let reason = gpt_reason.or_else(|| {
            if self.iokit_match_follow_remaining == 0 {
                None
            } else {
                iokit_match_reason
            }
        });
        let Some(reason) = reason else {
            return;
        };
        if gpt_reason.is_none() && iokit_match_reason.is_some() {
            self.iokit_match_follow_remaining = self.iokit_match_follow_remaining.saturating_sub(1);
        }
        self.partition_trace_remaining -= 1;

        if let Some(score) = (pc == 0xc044_ffda)
            .then(|| self.effective_guest_profile().guid_probe_score)
            .flatten()
        {
            if let Err(err) = self.bridge.write_word(self.cpu.regs[5], score) {
                debug!(
                    addr = format!("{:#x}", self.cpu.regs[5]),
                    ?err,
                    "failed to raise GUID partition probe score"
                );
            }
        }

        let sp = self.cpu.regs[13];
        let scan_set = self
            .bridge
            .read_word(sp.wrapping_add(0x30))
            .unwrap_or_default();
        let r0_partitions = self
            .bridge
            .read_word(self.cpu.regs[0].wrapping_add(0x68))
            .unwrap_or_default();
        let r4_partitions = self
            .bridge
            .read_word(self.cpu.regs[4].wrapping_add(0x68))
            .unwrap_or_default();
        let r6_partitions = self
            .bridge
            .read_word(self.cpu.regs[6].wrapping_add(0x68))
            .unwrap_or_default();
        let sp_best = self
            .bridge
            .read_word(sp.wrapping_add(0x10))
            .unwrap_or_default();
        let sp_provider = self
            .bridge
            .read_word(sp.wrapping_add(0x28))
            .unwrap_or_default();
        let sp_score = self
            .bridge
            .read_word(sp.wrapping_add(0x2c))
            .unwrap_or_default();
        let sp_probe = self
            .bridge
            .read_word(sp.wrapping_add(0x30))
            .unwrap_or_default();
        let r0_set_items = self
            .bridge
            .read_word(self.cpu.regs[0].wrapping_add(0x10))
            .map(|addr| self.guest_word_window(addr, 8))
            .unwrap_or_else(|_| "<fault>".to_string());
        let r4_set_items = self
            .bridge
            .read_word(self.cpu.regs[4].wrapping_add(0x10))
            .map(|addr| self.guest_word_window(addr, 8))
            .unwrap_or_else(|_| "<fault>".to_string());
        let r5_set_items = self
            .bridge
            .read_word(self.cpu.regs[5].wrapping_add(0x10))
            .map(|addr| self.guest_word_window(addr, 8))
            .unwrap_or_else(|_| "<fault>".to_string());
        let r6_set_items = self
            .bridge
            .read_word(self.cpu.regs[6].wrapping_add(0x10))
            .map(|addr| self.guest_word_window(addr, 8))
            .unwrap_or_else(|_| "<fault>".to_string());

        info!(
            pc = format!("{pc:#x}"),
            reason,
            r0 = format!("{:#x}", self.cpu.regs[0]),
            r1 = format!("{:#x}", self.cpu.regs[1]),
            r2 = format!("{:#x}", self.cpu.regs[2]),
            r3 = format!("{:#x}", self.cpu.regs[3]),
            r4 = format!("{:#x}", self.cpu.regs[4]),
            r5 = format!("{:#x}", self.cpu.regs[5]),
            r6 = format!("{:#x}", self.cpu.regs[6]),
            r7 = format!("{:#x}", self.cpu.regs[7]),
            r8 = format!("{:#x}", self.cpu.regs[8]),
            r9 = format!("{:#x}", self.cpu.regs[9]),
            r10 = format!("{:#x}", self.cpu.regs[10]),
            r11 = format!("{:#x}", self.cpu.regs[11]),
            r12 = format!("{:#x}", self.cpu.regs[12]),
            sp = format!("{:#x}", self.cpu.regs[13]),
            lr = format!("{:#x}", self.cpu.regs[14]),
            r0_words = self.guest_word_window(self.cpu.regs[0], 8),
            r1_words = self.guest_word_window(self.cpu.regs[1], 8),
            r2_words = self.guest_word_window(self.cpu.regs[2], 8),
            r3_words = self.guest_word_window(self.cpu.regs[3], 8),
            r4_words = self.guest_word_window(self.cpu.regs[4], 24),
            r5_words = self.guest_word_window(self.cpu.regs[5], 24),
            r6_words = self.guest_word_window(self.cpu.regs[6], 16),
            r8_words = self.guest_word_window(self.cpu.regs[8], 16),
            r10_words = self.guest_word_window(self.cpu.regs[10], 16),
            r11_words = self.guest_word_window(self.cpu.regs[11], 16),
            sp_words = self.guest_word_window(self.cpu.regs[13], 16),
            sp_best = format!("{sp_best:#x}"),
            sp_best_words = self.guest_word_window(sp_best, 16),
            sp_provider = format!("{sp_provider:#x}"),
            sp_provider_words = self.guest_word_window(sp_provider, 16),
            sp_score = format!("{sp_score:#x}"),
            sp_probe = format!("{sp_probe:#x}"),
            sp_probe_words = self.guest_word_window(sp_probe, 16),
            scan_set = format!("{scan_set:#x}"),
            scan_set_words = self.guest_word_window(scan_set, 12),
            r0_partitions = format!("{r0_partitions:#x}"),
            r0_partitions_words = self.guest_word_window(r0_partitions, 12),
            r4_partitions = format!("{r4_partitions:#x}"),
            r4_partitions_words = self.guest_word_window(r4_partitions, 12),
            r6_partitions = format!("{r6_partitions:#x}"),
            r6_partitions_words = self.guest_word_window(r6_partitions, 12),
            r0_set_items,
            r4_set_items,
            r5_set_items,
            r6_set_items,
            trail = self.recent_pc_trail(32),
            insns = self.insn_count,
            "partition scan trace"
        );
    }

    pub(super) fn trace_root_boot(&mut self, pc: u32) {
        let root_trace_allowed =
            self.root_trace_remaining > 0 && self.insn_count >= self.root_trace_start_insn;
        let root_boot_allowed = self.root_boot_trace_remaining > 0
            && self.insn_count >= self.root_boot_trace_start_insn;
        if !root_trace_allowed && !root_boot_allowed {
            return;
        }

        let Some((reason, boot_event)) = (match pc {
            KERNEL_CLOCK_INITIALIZE_CALENDAR => Some("clock_initialize_calendar"),
            KERNEL_ASSERT_WAIT => Some("assert_wait"),
            KERNEL_ASSERT_WAIT_TIMEOUT => Some("assert_wait_timeout"),
            KERNEL_ASSERT_WAIT_DEADLINE => Some("assert_wait_deadline"),
            KERNEL_THREAD_BLOCK_REASON => Some("thread_block_reason"),
            KERNEL_THREAD_BLOCK => Some("thread_block"),
            KERNEL_THREAD_WAIT => Some("thread_wait"),
            KERNEL_SEMAPHORE_TIMEDWAIT => Some("semaphore_timedwait"),
            KERNEL_SEMAPHORE_WAIT => Some("semaphore_wait"),
            KERNEL_WAKEUP => Some("wakeup"),
            KERNEL_WAKEUP_ONE => Some("wakeup_one"),
            KERNEL_IOLOCK_SLEEP => Some("IOLockSleep"),
            KERNEL_IOLOCK_SLEEP_DEADLINE => Some("IOLockSleepDeadline"),
            KERNEL_IOSYNCER_WAIT => Some("IOSyncer::wait"),
            KERNEL_IOKIT_INITIALIZE_TIME => Some("IOKitInitializeTime"),
            KERNEL_START_IOKIT => Some("StartIOKit"),
            KERNEL_IO_SERVICE_PUBLISH_RESOURCE_CSTR => Some("publishResource(char*)"),
            KERNEL_IO_SERVICE_ADD_NEEDED_RESOURCE => Some("addNeededResource(char*)"),
            KERNEL_IO_SERVICE_CHECK_RESOURCES => Some("IOService::checkResources"),
            KERNEL_IO_SERVICE_WAIT_QUIET => Some("IOService::waitQuiet"),
            KERNEL_IO_SERVICE_WAIT_FOR_SERVICE => Some("IOService::waitForService"),
            KERNEL_IO_SERVICE_WAIT_FOR_SERVICE_AFTER_SEM => {
                Some("IOService::waitForService after semaphore")
            }
            KERNEL_IO_SERVICE_RESOURCE_MATCHING_CSTR => Some("IOService::resourceMatching(char*)"),
            KERNEL_IO_SERVICE_WAIT_MATCH_IDLE => Some("IOService::waitMatchIdle"),
            KERNEL_IOKIT_BSD_INIT => Some("IOKitBSDInit"),
            KERNEL_IOBSD_NAME_MATCHING => Some("IOBSDNameMatching"),
            KERNEL_IOUUID_MATCHING => Some("IOUUIDMatching"),
            KERNEL_IOBSD_REGISTRY_ENTRY_FOR_DEVICE_TREE => Some("IOBSDRegistryEntryForDeviceTree"),
            KERNEL_IOBSD_REGISTRY_ENTRY_GET_DATA => Some("IOBSDRegistryEntryGetData"),
            KERNEL_DI_ROOT_IMAGE => Some("di_root_image"),
            KERNEL_VFS_MOUNTROOT => Some("vfs_mountroot"),
            KERNEL_DEVFS_KERNEL_MOUNT => Some("devfs_kernel_mount"),
            KERNEL_BSD_AUTOCONF => Some("bsd_autoconf"),
            KERNEL_BSD_INIT => Some("bsd_init"),
            KERNEL_BSD_INIT_CALL_IOKIT_INITIALIZE_TIME => Some("bsd_init -> IOKitInitializeTime"),
            KERNEL_BSD_INIT_CALL_BSD_AUTOCONF => Some("bsd_init -> bsd_autoconf"),
            KERNEL_BSD_INIT_CALL_VFS_MOUNTROOT => Some("bsd_init -> vfs_mountroot"),
            KERNEL_BSD_INIT_AFTER_VFS_MOUNTROOT => Some("bsd_init <- vfs_mountroot"),
            _ => None,
        })
        .map(|reason| {
            let boot_event = matches!(
                pc,
                KERNEL_CLOCK_INITIALIZE_CALENDAR
                    | KERNEL_IOKIT_INITIALIZE_TIME
                    | KERNEL_START_IOKIT
                    | KERNEL_IO_SERVICE_PUBLISH_RESOURCE_CSTR
                    | KERNEL_IO_SERVICE_ADD_NEEDED_RESOURCE
                    | KERNEL_IO_SERVICE_CHECK_RESOURCES
                    | KERNEL_IO_SERVICE_WAIT_QUIET
                    | KERNEL_IO_SERVICE_WAIT_FOR_SERVICE
                    | KERNEL_IO_SERVICE_WAIT_FOR_SERVICE_AFTER_SEM
                    | KERNEL_IO_SERVICE_RESOURCE_MATCHING_CSTR
                    | KERNEL_IO_SERVICE_WAIT_MATCH_IDLE
                    | KERNEL_IOKIT_BSD_INIT
                    | KERNEL_IOBSD_NAME_MATCHING
                    | KERNEL_IOUUID_MATCHING
                    | KERNEL_IOBSD_REGISTRY_ENTRY_FOR_DEVICE_TREE
                    | KERNEL_IOBSD_REGISTRY_ENTRY_GET_DATA
                    | KERNEL_DI_ROOT_IMAGE
                    | KERNEL_VFS_MOUNTROOT
                    | KERNEL_DEVFS_KERNEL_MOUNT
                    | KERNEL_BSD_AUTOCONF
                    | KERNEL_BSD_INIT
                    | KERNEL_BSD_INIT_CALL_IOKIT_INITIALIZE_TIME
                    | KERNEL_BSD_INIT_CALL_BSD_AUTOCONF
                    | KERNEL_BSD_INIT_CALL_VFS_MOUNTROOT
                    | KERNEL_BSD_INIT_AFTER_VFS_MOUNTROOT
            );
            (reason, boot_event)
        }) else {
            return;
        };
        if boot_event && root_boot_allowed {
            self.root_boot_trace_remaining -= 1;
        } else if root_trace_allowed {
            self.root_trace_remaining -= 1;
        } else {
            return;
        }

        let rootdev = self.bridge.read_word(KERNEL_ROOTDEV_GLOBAL).unwrap_or(0);
        let rootvnode = self.bridge.read_word(KERNEL_ROOTVNODE_GLOBAL).unwrap_or(0);
        let rootvp = self.bridge.read_word(KERNEL_ROOTVP_GLOBAL).unwrap_or(0);
        let rootfs = self.bridge.read_word(KERNEL_ROOTFS_GLOBAL).unwrap_or(0);
        let mountroot = self.bridge.read_word(KERNEL_MOUNTROOT_GLOBAL).unwrap_or(0);

        info!(
            pc = format!("{pc:#x}"),
            reason,
            r0 = format!("{:#x}", self.cpu.regs[0]),
            r1 = format!("{:#x}", self.cpu.regs[1]),
            r2 = format!("{:#x}", self.cpu.regs[2]),
            r3 = format!("{:#x}", self.cpu.regs[3]),
            r4 = format!("{:#x}", self.cpu.regs[4]),
            r5 = format!("{:#x}", self.cpu.regs[5]),
            r6 = format!("{:#x}", self.cpu.regs[6]),
            r7 = format!("{:#x}", self.cpu.regs[7]),
            sp = format!("{:#x}", self.cpu.regs[13]),
            lr = format!("{:#x}", self.cpu.regs[14]),
            cpsr = format!("{:#x}", self.cpu.cpsr.to_u32()),
            r0_str = ?self.guest_cstr(self.cpu.regs[0], 128),
            r1_str = ?self.guest_cstr(self.cpu.regs[1], 128),
            r2_str = ?self.guest_cstr(self.cpu.regs[2], 128),
            r0_words = self.guest_word_window(self.cpu.regs[0], 8),
            r1_words = self.guest_word_window(self.cpu.regs[1], 8),
            r2_words = self.guest_word_window(self.cpu.regs[2], 8),
            r3_words = self.guest_word_window(self.cpu.regs[3], 8),
            sp_words = self.guest_word_window(self.cpu.regs[13], 12),
            rootdev = format!("{rootdev:#x}"),
            rootdevice = ?self.guest_cstr(KERNEL_ROOTDEVICE_GLOBAL, 64),
            rootfs = format!("{rootfs:#x}"),
            rootvnode = format!("{rootvnode:#x}"),
            rootvp = format!("{rootvp:#x}"),
            mountroot = format!("{mountroot:#x}"),
            trail = self.recent_pc_trail(24),
            insns = self.insn_count,
            "root boot trace"
        );
    }
}
