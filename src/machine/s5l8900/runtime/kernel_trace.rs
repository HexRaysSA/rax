//! S5L platform kernel trace.
use super::*;

impl S5L8900Vcpu {
    pub(super) fn trace_sdio_power(&mut self, pc: u32, raw: u32) {
        if self.sdio_power_trace_remaining == 0 || self.insn_count < self.trace_start_insn {
            return;
        }

        let Some(reason) = (match pc {
            0xc04d_44d0 => Some("SDIO power/message window prologue"),
            0xc04d_44d4 => Some("SDIO load fifth argument"),
            0xc04d_44d8 => Some("SDIO load command constant"),
            0xc04d_44e0 => Some("SDIO compare command"),
            0xc04d_44e4 => Some("SDIO save this"),
            0xc04d_44e8 => Some("SDIO zero fifth-argument status"),
            0xc04d_44ec => Some("SDIO command branch"),
            0xc04d_4500 => Some("SDIO provider virtual call setup"),
            0xc04d_4508 => Some("SDIO provider virtual call"),
            0xc04d_450c => Some("SDIO provider call returned"),
            0xc04d_4540 => Some("SDIO copy fifth-argument value"),
            0xc04d_4548 => Some("SDIO store copied argument"),
            0xc04d_4554 => Some("SDIO second virtual call"),
            0xc04d_455c => Some("SDIO load failure return"),
            0xc04d_4564 => Some("SDIO write fifth-argument status"),
            _ => None,
        }) else {
            return;
        };

        self.sdio_power_trace_remaining -= 1;
        let regs = (0..16)
            .map(|i| format!("r{i}={:#x}", self.cpu.regs[i]))
            .collect::<Vec<_>>()
            .join(" ");
        let sp = self.cpu.regs[13];
        let stack_arg0 = self.bridge.read_word(sp.wrapping_add(0x14)).unwrap_or(0);
        let stack_arg1 = self.bridge.read_word(sp.wrapping_add(0x18)).unwrap_or(0);
        let stack_arg2 = self.bridge.read_word(sp.wrapping_add(0x1c)).unwrap_or(0);

        info!(
            pc = format!("{pc:#x}"),
            raw = format!("{raw:#010x}"),
            reason,
            regs,
            cpsr = format!("{:#x}", self.cpu.cpsr.to_u32()),
            stack_arg0 = format!("{stack_arg0:#x}"),
            stack_arg1 = format!("{stack_arg1:#x}"),
            stack_arg2 = format!("{stack_arg2:#x}"),
            stack_arg0_obj = self.iokit_object_summary(stack_arg0),
            stack_arg1_obj = self.iokit_object_summary(stack_arg1),
            stack_arg2_obj = self.iokit_object_summary(stack_arg2),
            r0_obj = self.iokit_object_summary(self.cpu.regs[0]),
            r1_obj = self.iokit_object_summary(self.cpu.regs[1]),
            r2_obj = self.iokit_object_summary(self.cpu.regs[2]),
            r3_obj = self.iokit_object_summary(self.cpu.regs[3]),
            r4_obj = self.iokit_object_summary(self.cpu.regs[4]),
            r5_obj = self.iokit_object_summary(self.cpu.regs[5]),
            r6_obj = self.iokit_object_summary(self.cpu.regs[6]),
            r7_obj = self.iokit_object_summary(self.cpu.regs[7]),
            r0_str = ?self.guest_cstr(self.cpu.regs[0], 192),
            r1_str = ?self.guest_cstr(self.cpu.regs[1], 192),
            r2_str = ?self.guest_cstr(self.cpu.regs[2], 192),
            r3_str = ?self.guest_cstr(self.cpu.regs[3], 192),
            r4_str = ?self.guest_cstr(self.cpu.regs[4], 192),
            r5_str = ?self.guest_cstr(self.cpu.regs[5], 192),
            r0_words = self.guest_word_window(self.cpu.regs[0], 24),
            r1_words = self.guest_word_window(self.cpu.regs[1], 16),
            r2_words = self.guest_word_window(self.cpu.regs[2], 16),
            r3_words = self.guest_word_window(self.cpu.regs[3], 16),
            r4_words = self.guest_word_window(self.cpu.regs[4], 24),
            r5_words = self.guest_word_window(self.cpu.regs[5], 24),
            r6_words = self.guest_word_window(self.cpu.regs[6], 16),
            r7_words = self.guest_word_window(self.cpu.regs[7], 16),
            stack_arg0_words = self.guest_word_window(stack_arg0, 24),
            sp_words = self.guest_word_window(sp, 32),
            stack_refs = self.stack_code_refs(sp, 160),
            trail = self.recent_pc_trail(96),
            insns = self.insn_count,
            "sdio power trace"
        );
    }

    pub(super) fn trace_iokit_message_path(&mut self, pc: u32, raw: u32) {
        if self.iokit_message_trace_remaining == 0 || self.insn_count < self.trace_start_insn {
            return;
        }

        let Some(reason) = (match pc {
            0xc013_3c38 => Some("IOService::messageClient entry"),
            0xc013_3c54 => Some("IOService::messageClient service cast call"),
            0xc013_3c58 => Some("IOService::messageClient service cast returned"),
            0xc013_3c6a => Some("IOService::messageClient direct message call"),
            0xc013_3c6c => Some("IOService::messageClient direct message returned"),
            0xc013_3c7c => Some("IOService::messageClient interest cast setup"),
            0xc013_3c82 => Some("IOService::messageClient interest cast call"),
            0xc013_3c86 => Some("IOService::messageClient interest cast returned"),
            0xc013_3ccc => Some("IOService::messageClient load arg size"),
            0xc013_3cd2 => Some("IOService::messageClient store arg size"),
            0xc013_3cd4 => Some("IOService::messageClient store argument"),
            0xc013_3cdc => Some("IOService::messageClient interest callback call"),
            0xc013_3cde => Some("IOService::messageClient interest callback returned"),
            0xc013_3e28 => Some("messageClients callback entry"),
            0xc013_3e4a => Some("messageClients callback store arg size"),
            0xc013_3e50 => Some("messageClients callback call messageClient"),
            0xc013_3e52 => Some("messageClients callback returned"),
            0xc013_3e60 => Some("IOService::messageClients entry"),
            0xc013_3e72 => Some("IOService::messageClients context initialized"),
            0xc013_3e82 => Some("IOService::messageClients applyToInterested call"),
            0xc013_3e84 => Some("IOService::messageClients applyToInterested returned"),
            _ => None,
        }) else {
            return;
        };

        self.iokit_message_trace_remaining -= 1;
        let regs = (0..16)
            .map(|i| format!("r{i}={:#x}", self.cpu.regs[i]))
            .collect::<Vec<_>>()
            .join(" ");
        let sp = self.cpu.regs[13];
        let context = match pc {
            0xc013_3e28..=0xc013_3e52 => self.cpu.regs[1],
            0xc013_3e60..=0xc013_3e84 => sp,
            _ => 0,
        };
        let context0 = self.bridge.read_word(context).unwrap_or(0);
        let context1 = self.bridge.read_word(context.wrapping_add(4)).unwrap_or(0);
        let context2 = self.bridge.read_word(context.wrapping_add(8)).unwrap_or(0);
        let context3 = self.bridge.read_word(context.wrapping_add(12)).unwrap_or(0);
        let context4 = self.bridge.read_word(context.wrapping_add(16)).unwrap_or(0);
        let stack_arg0 = self.bridge.read_word(sp).unwrap_or(0);
        let stack_arg1 = self.bridge.read_word(sp.wrapping_add(4)).unwrap_or(0);
        let message_client_arg_size = self.bridge.read_word(sp.wrapping_add(0x34)).unwrap_or(0);

        info!(
            pc = format!("{pc:#x}"),
            raw = format!("{raw:#010x}"),
            reason,
            regs,
            cpsr = format!("{:#x}", self.cpu.cpsr.to_u32()),
            context = format!("{context:#x}"),
            context0 = format!("{context0:#x}"),
            context1 = format!("{context1:#x}"),
            context2 = format!("{context2:#x}"),
            context3 = format!("{context3:#x}"),
            context4 = format!("{context4:#x}"),
            context0_obj = self.iokit_object_summary(context0),
            context1_obj = self.iokit_object_summary(context1),
            context2_obj = self.iokit_object_summary(context2),
            context3_obj = self.iokit_object_summary(context3),
            context4_obj = self.iokit_object_summary(context4),
            stack_arg0 = format!("{stack_arg0:#x}"),
            stack_arg1 = format!("{stack_arg1:#x}"),
            stack_arg0_obj = self.iokit_object_summary(stack_arg0),
            stack_arg1_obj = self.iokit_object_summary(stack_arg1),
            message_client_arg_size = format!("{message_client_arg_size:#x}"),
            r0_obj = self.iokit_object_summary(self.cpu.regs[0]),
            r1_obj = self.iokit_object_summary(self.cpu.regs[1]),
            r2_obj = self.iokit_object_summary(self.cpu.regs[2]),
            r3_obj = self.iokit_object_summary(self.cpu.regs[3]),
            r4_obj = self.iokit_object_summary(self.cpu.regs[4]),
            r5_obj = self.iokit_object_summary(self.cpu.regs[5]),
            r6_obj = self.iokit_object_summary(self.cpu.regs[6]),
            r8_obj = self.iokit_object_summary(self.cpu.regs[8]),
            r10_obj = self.iokit_object_summary(self.cpu.regs[10]),
            r11_obj = self.iokit_object_summary(self.cpu.regs[11]),
            r0_words = self.guest_word_window(self.cpu.regs[0], 16),
            r1_words = self.guest_word_window(self.cpu.regs[1], 16),
            r2_words = self.guest_word_window(self.cpu.regs[2], 16),
            r3_words = self.guest_word_window(self.cpu.regs[3], 16),
            r4_words = self.guest_word_window(self.cpu.regs[4], 16),
            r5_words = self.guest_word_window(self.cpu.regs[5], 16),
            r10_words = self.guest_word_window(self.cpu.regs[10], 16),
            context_words = self.guest_word_window(context, 16),
            sp_words = self.guest_word_window(sp, 40),
            stack_refs = self.stack_code_refs(sp, 192),
            trail = self.recent_pc_trail(96),
            insns = self.insn_count,
            "iokit message trace"
        );
    }

    pub(super) fn trace_pmqueue(&mut self, pc: u32, raw: u32) {
        if self.pmqueue_trace_remaining == 0 || self.insn_count < self.trace_start_insn {
            return;
        }

        let Some(reason) = (match pc {
            0xc013_d618 => Some("IOPMPowerStateQueue::featureChangeOccurred entry"),
            0xc013_d624 => Some("featureChangeOccurred before IOMalloc"),
            0xc013_d628 => Some("featureChangeOccurred after IOMalloc"),
            0xc013_d62c => Some("featureChangeOccurred allocated item"),
            0xc013_d630 => Some("featureChangeOccurred store item kind"),
            0xc013_d632 => Some("featureChangeOccurred store item message"),
            0xc013_d634 => Some("featureChangeOccurred store item service"),
            0xc013_d636 => Some("featureChangeOccurred item populated"),
            0xc013_d63a => Some("featureChangeOccurred enqueue item"),
            0xc013_d640 => Some("featureChangeOccurred signal work"),
            0xc013_d6d0 => Some("IOPMPowerStateQueue::unIdleOccurred entry"),
            0xc013_d6e4 => Some("unIdleOccurred after IOMalloc"),
            0xc013_d6ea => Some("unIdleOccurred store item kind"),
            0xc013_d6ee => Some("unIdleOccurred store item service"),
            0xc013_d6f0 => Some("unIdleOccurred store item arg"),
            0xc013_d700 => Some("unIdleOccurred enqueue item"),
            0xc013_d71c => Some("IOPMPowerStateQueue::checkForWork entry"),
            0xc013_d734 => Some("checkForWork load queue head"),
            0xc013_d738 => Some("checkForWork queue head loaded"),
            0xc013_d752 => Some("checkForWork selected item"),
            0xc013_d754 => Some("checkForWork item loaded"),
            0xc013_d760 => Some("checkForWork load item kind"),
            0xc013_d762 => Some("checkForWork load item message"),
            0xc013_d76a => Some("checkForWork load item service"),
            0xc013_d770 => Some("checkForWork branch on kind zero"),
            0xc013_d774 => Some("checkForWork branch on kind one"),
            0xc013_d7ae => Some("checkForWork feature-change dispatch"),
            0xc013_d7ba => Some("checkForWork feature-change message loaded"),
            0xc013_d7c0 => Some("checkForWork feature-change call"),
            _ => None,
        }) else {
            return;
        };

        let sp = self.cpu.regs[13];
        let item = match pc {
            0xc013_d628 => self.cpu.regs[0],
            0xc013_d62c..=0xc013_d640 => self.cpu.regs[1],
            0xc013_d6e4 => self.cpu.regs[0],
            0xc013_d6ea..=0xc013_d700 => self.cpu.regs[4],
            0xc013_d738 | 0xc013_d752 => self.bridge.read_word(sp.wrapping_add(8)).unwrap_or(0),
            0xc013_d754..=0xc013_d7c0 => self.cpu.regs[4],
            _ => 0,
        };
        let queue = match pc {
            0xc013_d618..=0xc013_d640 => self.cpu.regs[6],
            0xc013_d6d0..=0xc013_d700 => self.cpu.regs[5],
            0xc013_d71c => self.cpu.regs[0],
            0xc013_d734..=0xc013_d7c0 => self.cpu.regs[8],
            _ => 0,
        };
        let queue_head = if pc == 0xc013_d734 {
            self.bridge.read_word(self.cpu.regs[4]).unwrap_or(0)
        } else {
            self.bridge.read_word(queue.wrapping_add(0x24)).unwrap_or(0)
        };
        if matches!(pc, 0xc013_d71c..=0xc013_d7c0)
            && item == 0
            && queue_head == 0
            && std::env::var_os("RAX_S5L_PMQUEUE_TRACE_EMPTY").is_none()
        {
            return;
        }

        self.pmqueue_trace_remaining -= 1;

        let regs = (0..16)
            .map(|i| format!("r{i}={:#x}", self.cpu.regs[i]))
            .collect::<Vec<_>>()
            .join(" ");
        let item_next = self.bridge.read_word(item).unwrap_or(0);
        let item_kind = self.bridge.read_halfword(item.wrapping_add(4)).unwrap_or(0);
        let item_message = self.bridge.read_word(item.wrapping_add(8)).unwrap_or(0);
        let item_service = self.bridge.read_word(item.wrapping_add(12)).unwrap_or(0);
        let queue_lock = self.bridge.read_word(queue.wrapping_add(0x28)).unwrap_or(0);

        info!(
            pc = format!("{pc:#x}"),
            raw = format!("{raw:#010x}"),
            reason,
            regs,
            cpsr = format!("{:#x}", self.cpu.cpsr.to_u32()),
            item = format!("{item:#x}"),
            item_next = format!("{item_next:#x}"),
            item_kind = format!("{item_kind:#x}"),
            item_message = format!("{item_message:#x}"),
            item_service = format!("{item_service:#x}"),
            queue = format!("{queue:#x}"),
            queue_head = format!("{queue_head:#x}"),
            queue_lock = format!("{queue_lock:#x}"),
            item_service_obj = self.iokit_object_summary(item_service),
            r0_obj = self.iokit_object_summary(self.cpu.regs[0]),
            r1_obj = self.iokit_object_summary(self.cpu.regs[1]),
            r2_obj = self.iokit_object_summary(self.cpu.regs[2]),
            r3_obj = self.iokit_object_summary(self.cpu.regs[3]),
            r4_obj = self.iokit_object_summary(self.cpu.regs[4]),
            r5_obj = self.iokit_object_summary(self.cpu.regs[5]),
            r6_obj = self.iokit_object_summary(self.cpu.regs[6]),
            r8_obj = self.iokit_object_summary(self.cpu.regs[8]),
            r10_obj = self.iokit_object_summary(self.cpu.regs[10]),
            item_words = self.guest_word_window(item, 8),
            queue_words = self.guest_word_window(queue, 16),
            r0_words = self.guest_word_window(self.cpu.regs[0], 8),
            r1_words = self.guest_word_window(self.cpu.regs[1], 8),
            r2_words = self.guest_word_window(self.cpu.regs[2], 8),
            r3_words = self.guest_word_window(self.cpu.regs[3], 8),
            r4_words = self.guest_word_window(self.cpu.regs[4], 8),
            r5_words = self.guest_word_window(self.cpu.regs[5], 8),
            r6_words = self.guest_word_window(self.cpu.regs[6], 8),
            r8_words = self.guest_word_window(self.cpu.regs[8], 8),
            r10_words = self.guest_word_window(self.cpu.regs[10], 8),
            sp_words = self.guest_word_window(sp, 32),
            stack_refs = self.stack_code_refs(sp, 160),
            trail = self.recent_pc_trail(96),
            insns = self.insn_count,
            "iopm queue trace"
        );
    }

    pub(super) fn trace_apple_arm_function(&mut self, pc: u32, raw: u32) {
        if self.apple_arm_function_trace_remaining == 0 || self.insn_count < self.trace_start_insn {
            return;
        }

        let Some(reason) = (match pc {
            0xc015_7f04 => Some("AppleARMFunction::withProvider(char*) entry"),
            0xc015_7f0c => Some("AppleARMFunction::withProvider(char*) make symbol"),
            0xc015_7f18 => Some("AppleARMFunction::withProvider(char*) symbol overload returned"),
            0xc015_7f1c => Some("AppleARMFunction::withProvider(char*) release symbol"),
            0xc015_7e1c => Some("AppleARMFunction::withProvider(symbol) entry"),
            0xc015_7e40 => Some("AppleARMFunction provider getProperty call"),
            0xc015_7e46 => Some("AppleARMFunction provider getProperty returned"),
            0xc015_7e4c => Some("AppleARMFunction OSData safeMetaCast"),
            0xc015_7e54 => Some("AppleARMFunction OSData length call"),
            0xc015_7e5a => Some("AppleARMFunction OSData length returned"),
            0xc015_7e60 => Some("AppleARMFunction parent symbol"),
            0xc015_7e6c => Some("AppleARMFunction empty data"),
            0xc015_7e78 => Some("AppleARMFunction propertyMatching call"),
            0xc015_7e7c => Some("AppleARMFunction waitForService call"),
            0xc015_7e82 => Some("AppleARMFunction waitForService returned"),
            0xc015_7e84 => Some("AppleARMFunction function object load"),
            KERNEL_IO_SERVICE_WAIT_FOR_SERVICE => Some("IOService::waitForService entry"),
            KERNEL_IO_SERVICE_WAIT_FOR_SERVICE_AFTER_SEM => {
                Some("IOService::waitForService after semaphore")
            }
            _ => None,
        }) else {
            return;
        };

        self.apple_arm_function_trace_remaining -= 1;
        let regs = (0..16)
            .map(|i| format!("r{i}={:#x}", self.cpu.regs[i]))
            .collect::<Vec<_>>()
            .join(" ");
        let sp = self.cpu.regs[13];

        info!(
            pc = format!("{pc:#x}"),
            raw = format!("{raw:#010x}"),
            reason,
            regs,
            cpsr = format!("{:#x}", self.cpu.cpsr.to_u32()),
            r0_str = ?self.guest_cstr(self.cpu.regs[0], 128),
            r1_str = ?self.guest_cstr(self.cpu.regs[1], 128),
            r2_str = ?self.guest_cstr(self.cpu.regs[2], 128),
            r5_str = ?self.guest_cstr(self.cpu.regs[5], 128),
            r10_str = ?self.guest_cstr(self.cpu.regs[10], 128),
            r0_words = self.guest_word_window(self.cpu.regs[0], 12),
            r1_words = self.guest_word_window(self.cpu.regs[1], 12),
            r2_words = self.guest_word_window(self.cpu.regs[2], 12),
            r3_words = self.guest_word_window(self.cpu.regs[3], 12),
            r4_words = self.guest_word_window(self.cpu.regs[4], 16),
            r5_words = self.guest_word_window(self.cpu.regs[5], 16),
            r6_words = self.guest_word_window(self.cpu.regs[6], 16),
            r8_words = self.guest_word_window(self.cpu.regs[8], 16),
            r9_words = self.guest_word_window(self.cpu.regs[9], 16),
            r10_words = self.guest_word_window(self.cpu.regs[10], 16),
            r11_words = self.guest_word_window(self.cpu.regs[11], 16),
            sp_words = self.guest_word_window(sp, 24),
            stack_refs = self.stack_code_refs(sp, 96),
            trail = self.recent_pc_trail(48),
            insns = self.insn_count,
            "apple arm function trace"
        );
    }

    pub(super) fn trace_ioreg_free(&mut self, pc: u32, raw: u32) {
        if self.ioreg_free_trace_remaining == 0 || self.insn_count < self.trace_start_insn {
            return;
        }

        let Some(reason) = (match pc {
            0xc012_2c48 => Some("OSObject::taggedRelease free object"),
            0xc012_2c53 => Some("OSObject::taggedRelease free returned"),
            0xc013_07d4 => Some("IORegistryEntry::free entry"),
            0xc013_07f8 => Some("IORegistryEntry::free check registered"),
            0xc013_0814 => Some("IORegistryEntry::free parent check returned"),
            0xc013_083e => Some("IORegistryEntry::free IOPanic call"),
            0xc013_0840 => Some("IORegistryEntry::free IOPanic"),
            KERNEL_IOPANIC => Some("_IOPanic entry"),
            _ => None,
        }) else {
            return;
        };

        self.ioreg_free_trace_remaining -= 1;

        let sp = self.cpu.regs[13];
        let tagged_release_obj = self.bridge.read_word(sp).unwrap_or(0);
        let free_obj = match pc {
            0xc012_2c48 | 0xc012_2c53 => tagged_release_obj,
            0xc013_07d4 => self.cpu.regs[0],
            0xc013_07f8 | 0xc013_0814 | 0xc013_083e | 0xc013_0840 => self.cpu.regs[4],
            _ => 0,
        };
        let regs = (0..16)
            .map(|i| format!("r{i}={:#x}", self.cpu.regs[i]))
            .collect::<Vec<_>>()
            .join(" ");

        info!(
            pc = format!("{pc:#x}"),
            raw = format!("{raw:#010x}"),
            reason,
            regs,
            cpsr = format!("{:#x}", self.cpu.cpsr.to_u32()),
            free_obj = self.iokit_object_summary(free_obj),
            tagged_release_obj = self.iokit_object_summary(tagged_release_obj),
            r0_obj = self.iokit_object_summary(self.cpu.regs[0]),
            r1_obj = self.iokit_object_summary(self.cpu.regs[1]),
            r2_obj = self.iokit_object_summary(self.cpu.regs[2]),
            r3_obj = self.iokit_object_summary(self.cpu.regs[3]),
            r4_obj = self.iokit_object_summary(self.cpu.regs[4]),
            r5_obj = self.iokit_object_summary(self.cpu.regs[5]),
            r0_str = ?self.guest_cstr(self.cpu.regs[0], 192),
            r1_str = ?self.guest_cstr(self.cpu.regs[1], 192),
            r2_str = ?self.guest_cstr(self.cpu.regs[2], 192),
            r3_str = ?self.guest_cstr(self.cpu.regs[3], 192),
            r4_str = ?self.guest_cstr(self.cpu.regs[4], 192),
            r5_str = ?self.guest_cstr(self.cpu.regs[5], 192),
            r4_words = self.guest_word_window(self.cpu.regs[4], 24),
            r5_words = self.guest_word_window(self.cpu.regs[5], 24),
            sp_words = self.guest_word_window(sp, 32),
            stack_refs = self.stack_code_refs(sp, 128),
            trail = self.recent_pc_trail(64),
            insns = self.insn_count,
            "iokit final free trace"
        );
    }

    pub(super) fn trace_iokit_object_watch(&mut self, pc: u32, raw: u32) {
        if self.iokit_watch_trace_remaining == 0 || self.insn_count < self.trace_start_insn {
            return;
        }
        let Some(watch) = self.iokit_watch_object else {
            return;
        };

        let Some(reason) = (match pc {
            0xc005_c630 => Some("_hw_compare_and_store entry"),
            0xc005_c634 => Some("_hw_compare_and_store ldrex"),
            0xc005_c63a => Some("_hw_compare_and_store compare"),
            0xc005_c63e => Some("_hw_compare_and_store strex"),
            0xc005_c642 => Some("_hw_compare_and_store result"),
            0xc012_2b5e => Some("OSObject::taggedRetain entry"),
            0xc012_2b96 => Some("OSObject::taggedRetain compare/store"),
            0xc012_2b9e => Some("OSObject::taggedRetain return"),
            0xc012_2bb8 => Some("OSObject::taggedRelease entry"),
            0xc012_2bc6 => Some("OSObject::taggedRelease(count) entry"),
            0xc012_2bf0 => Some("OSObject::taggedRelease loaded count"),
            0xc012_2c1c => Some("OSObject::taggedRelease compare/store"),
            0xc012_2c24 => Some("OSObject::taggedRelease retry"),
            0xc012_2c48 => Some("OSObject::taggedRelease free object"),
            0xc012_2c53 => Some("OSObject::taggedRelease free returned"),
            0xc012_2c68 => Some("OSObject::release entry"),
            0xc012_2c76 => Some("OSObject::retain entry"),
            0xc012_5c66 => Some("OSOrderedSet::flushCollection item load"),
            0xc012_5c70 => Some("OSOrderedSet::flushCollection release item"),
            0xc012_5c76 => Some("OSOrderedSet::flushCollection item released"),
            0xc012_5ce8 => Some("OSOrderedSet::setObject retain item"),
            0xc013_07d4 => Some("IORegistryEntry::free entry"),
            0xc013_07f8 => Some("IORegistryEntry::free check registered"),
            0xc013_0814 => Some("IORegistryEntry::free parent check returned"),
            0xc013_083e => Some("IORegistryEntry::free IOPanic call"),
            0xc013_0840 => Some("IORegistryEntry::free IOPanic"),
            0xc013_20ba => Some("IORegistryIterator::reset store visited set"),
            0xc013_20dc => Some("IORegistryIterator::free reset returned"),
            0xc013_2116 => Some("IORegistryIterator::getNextObjectFlat release current"),
            0xc013_2136 => Some("IORegistryIterator::getNextObjectFlat retain next"),
            0xc013_213a => Some("IORegistryIterator::getNextObjectFlat store current"),
            0xc013_4b7a => Some("IOService::getExistingServices got next service"),
            0xc013_4ba0 => Some("IOService::getExistingServices passiveMatch returned"),
            0xc013_4bd6 => Some("IOService::getExistingServices release iterator"),
            0xc013_4bde => Some("IOService::getExistingServices iterator released"),
            KERNEL_IOPANIC => Some("_IOPanic entry"),
            _ => None,
        }) else {
            return;
        };

        let retain_word = watch.wrapping_add(4);
        let sp = self.cpu.regs[13];
        let tagged_release_obj = self.bridge.read_word(sp).unwrap_or(0);
        let mut hits = Vec::new();
        let mut operand_hit = false;

        let mut push_hit = |hit: &'static str| {
            operand_hit = true;
            hits.push(hit.to_string());
        };

        if matches!(
            pc,
            0xc005_c630
                | 0xc005_c634
                | 0xc005_c63a
                | 0xc005_c63e
                | 0xc005_c642
                | 0xc012_2b96
                | 0xc012_2b9e
                | 0xc012_2bf0
                | 0xc012_2c1c
                | 0xc012_2c24
        ) && self.cpu.regs[2] == retain_word
        {
            push_hit("retain_word_operand");
        }
        if matches!(pc, 0xc012_2b96 | 0xc012_2b9e) && self.cpu.regs[5] == retain_word {
            push_hit("retain_word_saved");
        }
        if matches!(
            pc,
            0xc012_2b5e | 0xc012_2bb8 | 0xc012_2bc6 | 0xc012_2c68 | 0xc012_2c76
        ) && self.cpu.regs[0] == watch
        {
            push_hit("object_operand");
        }
        if matches!(pc, 0xc012_2c48 | 0xc012_2c53) && tagged_release_obj == watch {
            push_hit("free_stack_object");
        }

        if matches!(pc, 0xc012_5c66 | 0xc012_5c70 | 0xc012_5c76) {
            if let Some(item) = self.collection_item(self.cpu.regs[4], self.cpu.regs[5]) {
                if item == watch {
                    push_hit("ordered_set_current_item");
                }
            }
        }
        if matches!(pc, 0xc012_5c70 | 0xc012_5c76) && self.cpu.regs[0] == watch {
            push_hit("ordered_set_release_operand");
        }
        if pc == 0xc012_5ce8
            && (self.cpu.regs[0] == watch || self.cpu.regs[1] == watch || self.cpu.regs[2] == watch)
        {
            push_hit("ordered_set_set_object_operand");
        }
        if matches!(pc, 0xc013_07d4) && self.cpu.regs[0] == watch {
            push_hit("ioreg_free_entry_object");
        }
        if matches!(pc, 0xc013_07f8 | 0xc013_0814 | 0xc013_083e | 0xc013_0840)
            && self.cpu.regs[4] == watch
        {
            push_hit("ioreg_free_this");
        }
        if matches!(pc, 0xc013_2116 | 0xc013_2136 | 0xc013_213a)
            && (self.cpu.regs[0] == watch || self.cpu.regs[4] == watch)
        {
            push_hit("registry_iterator_object");
        }
        if matches!(pc, 0xc013_4b7a | 0xc013_4ba0) && self.cpu.regs[0] == watch {
            push_hit("get_existing_services_candidate");
        }
        if matches!(pc, 0xc013_4bd6 | 0xc013_4bde)
            && self.bridge.read_word(sp).is_ok_and(|value| value == watch)
        {
            push_hit("get_existing_services_stack_result");
        }
        if pc == KERNEL_IOPANIC && (self.cpu.regs[0] == watch || self.cpu.regs[4] == watch) {
            push_hit("panic_object");
        }

        if !operand_hit {
            return;
        }

        if std::env::var_os("RAX_S5L_IOKIT_OBJECT_STACK_HITS").is_some() {
            for i in 0..16 {
                let value = self.cpu.regs[i];
                if value == watch {
                    hits.push(format!("r{i}=object"));
                } else if value == retain_word {
                    hits.push(format!("r{i}=retain_word"));
                }
            }

            let stack_words = 64;
            for i in 0..stack_words {
                let addr = sp.wrapping_add(i * 4);
                if let Ok(value) = self.bridge.read_word(addr) {
                    if value == watch {
                        hits.push(format!("sp+{:#x}=object", i * 4));
                    } else if value == retain_word {
                        hits.push(format!("sp+{:#x}=retain_word", i * 4));
                    }
                }
            }
            if tagged_release_obj == watch {
                hits.push("tagged_release_stack_object".to_string());
            }

            for &(name, reg) in &[
                ("r0_collection", 0usize),
                ("r1_collection", 1),
                ("r2_collection", 2),
                ("r3_collection", 3),
                ("r4_collection", 4),
                ("r5_collection", 5),
                ("r8_collection", 8),
                ("r10_collection", 10),
                ("r11_collection", 11),
            ] {
                if self.collection_contains_object(self.cpu.regs[reg], watch) {
                    hits.push(name.to_string());
                }
            }
        }

        self.iokit_watch_trace_remaining -= 1;
        let regs = (0..16)
            .map(|i| format!("r{i}={:#x}", self.cpu.regs[i]))
            .collect::<Vec<_>>()
            .join(" ");

        info!(
            pc = format!("{pc:#x}"),
            raw = format!("{raw:#010x}"),
            reason,
            hits = hits.join(" "),
            watch = self.iokit_object_summary(watch),
            watch_rc = format!("{:#x}", self.bridge.read_word(retain_word).unwrap_or(0)),
            regs,
            cpsr = format!("{:#x}", self.cpu.cpsr.to_u32()),
            r0_obj = self.iokit_object_summary(self.cpu.regs[0]),
            r1_obj = self.iokit_object_summary(self.cpu.regs[1]),
            r2_obj = self.iokit_object_summary(self.cpu.regs[2]),
            r3_obj = self.iokit_object_summary(self.cpu.regs[3]),
            r4_obj = self.iokit_object_summary(self.cpu.regs[4]),
            r5_obj = self.iokit_object_summary(self.cpu.regs[5]),
            r8_obj = self.iokit_object_summary(self.cpu.regs[8]),
            r10_obj = self.iokit_object_summary(self.cpu.regs[10]),
            r11_obj = self.iokit_object_summary(self.cpu.regs[11]),
            r4_iter = self.iokit_iterator_summary(self.cpu.regs[4]),
            r4_set = self.iokit_collection_summary(self.cpu.regs[4]),
            r8_set = self.iokit_collection_summary(self.cpu.regs[8]),
            tagged_release_obj = self.iokit_object_summary(tagged_release_obj),
            sp_words = self.guest_word_window(sp, 32),
            stack_refs = self.stack_code_refs(sp, 128),
            trail = self.recent_pc_trail(64),
            insns = self.insn_count,
            "iokit object watch"
        );
    }

    pub(super) fn trace_iokit_lifetime(&mut self, pc: u32, raw: u32) {
        if self.iokit_lifetime_trace_remaining == 0 || self.insn_count < self.trace_start_insn {
            return;
        }

        let Some(reason) = (match pc {
            0xc013_4b1c => Some("IOService::getExistingServices entry"),
            0xc013_4b58 => Some("IOService::getExistingServices make iterator"),
            0xc013_4b6a => Some("IOService::getExistingServices reset iterator"),
            0xc013_4b7a => Some("IOService::getExistingServices got next service"),
            0xc013_4b80 => Some("IOService::getExistingServices service state filter"),
            0xc013_4b92 => Some("IOService::getExistingServices passiveMatch call"),
            0xc013_4ba0 => Some("IOService::getExistingServices passiveMatch returned"),
            0xc013_4ba4 => Some("IOService::getExistingServices matched service"),
            0xc013_4bd6 => Some("IOService::getExistingServices release iterator"),
            0xc013_4bde => Some("IOService::getExistingServices iterator released"),
            0xc013_4bec => Some("IOService::getExistingServices return"),
            0xc013_4c5e => Some("IOService::getExistingServices direct result"),
            0xc012_3d58 => Some("OSCollectionIterator::free entry"),
            0xc012_3d64 => Some("OSCollectionIterator::free release snapshot"),
            0xc012_3d88 => Some("OSCollectionIterator::free release collection"),
            0xc012_3d92 => Some("OSCollectionIterator::free collection release call"),
            0xc012_5b76 => Some("OSOrderedSet::free entry"),
            0xc012_5b88 => Some("OSOrderedSet::free after flush"),
            0xc012_5c4c => Some("OSOrderedSet::flushCollection entry"),
            0xc012_5c66 => Some("OSOrderedSet::flushCollection item load"),
            0xc012_5c70 => Some("OSOrderedSet::flushCollection release item"),
            0xc012_5c76 => Some("OSOrderedSet::flushCollection item released"),
            0xc012_2b5e if self.iokit_retain_trace => Some("OSObject::taggedRetain entry"),
            0xc012_2b9e if self.iokit_retain_trace => Some("OSObject::taggedRetain return"),
            0xc012_2bb8 if self.iokit_retain_trace => Some("OSObject::taggedRelease entry"),
            0xc012_2bc6 if self.iokit_retain_trace => Some("OSObject::taggedRelease(count) entry"),
            0xc012_2c48 if self.iokit_retain_trace => Some("OSObject::taggedRelease free object"),
            0xc012_2c53 if self.iokit_retain_trace => Some("OSObject::taggedRelease free returned"),
            0xc012_2c68 if self.iokit_retain_trace => Some("OSObject::release entry"),
            0xc012_2c76 if self.iokit_retain_trace => Some("OSObject::retain entry"),
            0xc013_07d4 => Some("IORegistryEntry::free entry"),
            0xc013_07f8 => Some("IORegistryEntry::free check registered"),
            0xc013_0814 => Some("IORegistryEntry::free parent check returned"),
            0xc013_083e => Some("IORegistryEntry::free IOPanic call"),
            0xc013_0840 => Some("IORegistryEntry::free IOPanic"),
            KERNEL_IOPANIC => Some("_IOPanic entry"),
            _ => None,
        }) else {
            return;
        };

        self.iokit_lifetime_trace_remaining -= 1;
        let regs = (0..16)
            .map(|i| format!("r{i}={:#x}", self.cpu.regs[i]))
            .collect::<Vec<_>>()
            .join(" ");
        let sp = self.cpu.regs[13];
        let stack_service = self.bridge.read_word(sp).unwrap_or(0);

        info!(
            pc = format!("{pc:#x}"),
            raw = format!("{raw:#010x}"),
            reason,
            regs,
            cpsr = format!("{:#x}", self.cpu.cpsr.to_u32()),
            r0_obj = self.iokit_object_summary(self.cpu.regs[0]),
            r1_obj = self.iokit_object_summary(self.cpu.regs[1]),
            r2_obj = self.iokit_object_summary(self.cpu.regs[2]),
            r3_obj = self.iokit_object_summary(self.cpu.regs[3]),
            r4_obj = self.iokit_object_summary(self.cpu.regs[4]),
            r4_iter = self.iokit_iterator_summary(self.cpu.regs[4]),
            r4_set = self.iokit_collection_summary(self.cpu.regs[4]),
            r5_obj = self.iokit_object_summary(self.cpu.regs[5]),
            r8_obj = self.iokit_object_summary(self.cpu.regs[8]),
            r8_set = self.iokit_collection_summary(self.cpu.regs[8]),
            r10_obj = self.iokit_object_summary(self.cpu.regs[10]),
            r11_obj = self.iokit_object_summary(self.cpu.regs[11]),
            stack0_obj = self.iokit_object_summary(stack_service),
            sp_words = self.guest_word_window(sp, 20),
            stack_refs = self.stack_code_refs(sp, 96),
            trail = self.recent_pc_trail(48),
            insns = self.insn_count,
            "iokit lifetime trace"
        );
    }

    pub(super) fn iokit_object_summary(&self, addr: u32) -> String {
        if addr == 0 {
            return String::from("<null>");
        }

        let word = |off: u32| self.bridge.read_word(addr.wrapping_add(off)).unwrap_or(0);
        format!(
            "obj={addr:#x} vt={:#x} rc={:#x} off8={:#x} plane={:#x} props={:#x} state={:#x} words=[{}]",
            word(0),
            word(4),
            word(8),
            word(0xc),
            word(0x10),
            word(0x24),
            self.guest_word_window(addr, 10)
        )
    }

    pub(super) fn iokit_iterator_summary(&self, addr: u32) -> String {
        if addr == 0 {
            return String::from("<null>");
        }

        let word = |off: u32| self.bridge.read_word(addr.wrapping_add(off)).unwrap_or(0);
        let collection = word(0x8);
        let snapshot = word(0xc);
        let cursor = word(0x10);
        let valid = self.bridge.read_byte(addr.wrapping_add(0x14)).unwrap_or(0);
        format!(
            "iter={addr:#x} vt={:#x} rc={:#x} collection={collection:#x} snapshot={snapshot:#x} cursor={cursor:#x} valid={valid:#x} words=[{}] collection=[{}]",
            word(0),
            word(4),
            self.guest_word_window(addr, 8),
            self.iokit_collection_summary(collection)
        )
    }

    pub(super) fn collection_item(&self, addr: u32, index: u32) -> Option<u32> {
        let items = self.bridge.read_word(addr.wrapping_add(0x10)).ok()?;
        let count = self.bridge.read_word(addr.wrapping_add(0x1c)).ok()?;
        if index >= count {
            return None;
        }
        self.bridge.read_word(items.wrapping_add(index * 4)).ok()
    }

    pub(super) fn collection_contains_object(&self, addr: u32, needle: u32) -> bool {
        if addr == 0 || needle == 0 {
            return false;
        }
        let Ok(items) = self.bridge.read_word(addr.wrapping_add(0x10)) else {
            return false;
        };
        let Ok(count) = self.bridge.read_word(addr.wrapping_add(0x1c)) else {
            return false;
        };
        for i in 0..count.min(64) {
            if self
                .bridge
                .read_word(items.wrapping_add(i * 4))
                .is_ok_and(|item| item == needle)
            {
                return true;
            }
        }
        false
    }

    pub(super) fn iokit_collection_summary(&self, addr: u32) -> String {
        if addr == 0 {
            return String::from("<null>");
        }

        let word = |off: u32| self.bridge.read_word(addr.wrapping_add(off)).unwrap_or(0);
        let items = word(0x10);
        let count = word(0x1c);
        let capacity = word(0x20);
        let shown = count.min(8);
        let mut entries = Vec::new();
        for i in 0..shown {
            let item = self
                .bridge
                .read_word(items.wrapping_add(i * 4))
                .unwrap_or(0);
            let retain = if item == 0 {
                0
            } else {
                self.bridge.read_word(item.wrapping_add(4)).unwrap_or(0)
            };
            entries.push(format!("{i}:{item:#x}/rc={retain:#x}"));
        }
        format!(
            "collection={addr:#x} vt={:#x} rc={:#x} items={items:#x} count={count:#x} cap={capacity:#x} entries=[{}] words=[{}]",
            word(0),
            word(4),
            entries.join(","),
            self.guest_word_window(addr, 10)
        )
    }
}
