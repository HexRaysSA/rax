//! Actual TCP/RSP control of multiple software CPUs through the VMM run loop.
use super::execution_tests::{BSP, Fixture};
use super::*;
use crate::debug::gdb::{GdbCommand, create_channels};
use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::mpsc::Sender;

struct Running {
    stream: Option<TcpStream>,
    address: std::net::SocketAddr,
    commands: Sender<GdbCommand>,
    vm: Option<std::thread::JoinHandle<()>>,
    server: Option<std::thread::JoinHandle<()>>,
    server_stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
}
impl Running {
    fn listen(count: u8) -> Self {
        let (client, channels) = create_channels();
        let commands = client.cmd_tx.clone();
        let (address, server, server_stop) = crate::debug::gdb::test_support::serve(client);
        let worker = std::thread::spawn(move || {
            let mut fixture = Fixture::new(count);
            fixture.write(0x1000, &0x2003u64.to_le_bytes());
            fixture.write(0x2000, &0x3003u64.to_le_bytes());
            fixture.write(0x3000, &0x83u64.to_le_bytes());
            let original = fixture.vm.vcpus[0].get_state().unwrap();
            for index in 0..usize::from(count) {
                let mut state = original.clone();
                let CpuState::X86_64(state) = &mut state else {
                    unreachable!()
                };
                state.regs.rip = BSP + 256 * index as u64;
                state.regs.rax = 0x100 + index as u64;
                state.sregs.cr0 |= 1 << 31;
                state.sregs.cr3 = 0x1000;
                state.sregs.cr4 |= 1 << 5;
                state.sregs.efer = (1 << 8) | (1 << 10);
                state.sregs.cs.l = true;
                state.sregs.cs.db = false;
                let state = CpuState::X86_64(state.clone());
                fixture.vm.vcpus[index].set_state(&state).unwrap();
                fixture.vm.vcpus[index].set_debugger_active(true);
                fixture.write(BSP + 256 * index as u64, &[0x48, 0xff, 0xc0, 0xeb, 0xfb]);
            }
            fixture.vm.coordinator.online.fill(true);
            fixture.vm.gdb_channels = Some(channels);
            fixture.vm.gdb_stopped = true;
            fixture.vm.run().unwrap();
        });
        Self {
            stream: None,
            address,
            commands,
            vm: Some(worker),
            server: Some(server),
            server_stop,
        }
    }
    fn new(count: u8) -> Self {
        let mut vm = Self::listen(count);
        let stream = TcpStream::connect(vm.address).unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(30)))
            .unwrap();
        vm.stream = Some(stream);
        vm
    }
    fn packet(&mut self, payload: &str) -> String {
        let stream = self.stream.as_mut().unwrap();
        let sum = payload.bytes().fold(0u8, u8::wrapping_add);
        write!(stream, "${payload}#{sum:02x}").unwrap();
        let mut byte = [0];
        loop {
            stream.read_exact(&mut byte).unwrap();
            if byte[0] == b'$' {
                break;
            }
        }
        let mut result = Vec::new();
        loop {
            stream.read_exact(&mut byte).unwrap();
            if byte[0] == b'#' {
                break;
            }
            result.push(byte[0]);
        }
        let mut check = [0; 2];
        stream.read_exact(&mut check).unwrap();
        assert_eq!(
            u8::from_str_radix(std::str::from_utf8(&check).unwrap(), 16).unwrap(),
            result.iter().fold(0u8, |a, b| a.wrapping_add(*b))
        );
        stream.write_all(b"+").unwrap();
        String::from_utf8(result).unwrap()
    }
    fn rax(&mut self, thread: usize) -> u64 {
        assert_eq!(self.packet(&format!("Hg{thread:x}")), "OK");
        let raw = self.packet("g");
        let bytes: Vec<_> = (0..16)
            .step_by(2)
            .map(|n| u8::from_str_radix(&raw[n..n + 2], 16).unwrap())
            .collect();
        u64::from_le_bytes(bytes.try_into().unwrap())
    }
}
impl Drop for Running {
    fn drop(&mut self) {
        if let Some(stream) = &self.stream {
            let _ = stream.shutdown(Shutdown::Both);
        }
        self.server_stop
            .store(true, std::sync::atomic::Ordering::SeqCst);
        if let Ok(wake) = TcpStream::connect(self.address) {
            let _ = wake.shutdown(Shutdown::Both);
        }
        let _ = self.commands.send(GdbCommand::Kill);
        if let Some(worker) = self.vm.take() {
            let result = worker.join();
            if !std::thread::panicking() {
                assert!(result.is_ok(), "VMM worker panicked");
            }
        }
        if let Some(worker) = self.server.take() {
            let _ = worker.join();
        }
    }
}

#[test]
fn rsp_inventory_lists_every_configured_cpu() {
    for count in [2, 4] {
        let mut vm = Running::new(count);
        let expected = format!(
            "m{}",
            (1..=count)
                .map(|n| format!("{n:x}"))
                .collect::<Vec<_>>()
                .join(",")
        );
        assert_eq!(vm.packet("qfThreadInfo"), expected);
        assert_eq!(vm.packet("qsThreadInfo"), "l");
    }
}
#[test]
fn rsp_register_selection_reads_the_selected_application_cpu() {
    let mut vm = Running::new(2);
    assert_eq!(vm.rax(2), 0x101);
    assert_eq!(vm.rax(1), 0x100);
}
#[test]
fn rsp_application_cpu_step_leaves_the_boot_cpu_parked_and_reports_its_thread() {
    let mut vm = Running::new(2);
    assert_eq!(vm.packet("Hc2"), "OK");
    assert_eq!(vm.packet("s"), "T05thread:2;core:1;");
    assert_eq!(vm.rax(1), 0x100);
    assert_eq!(vm.rax(2), 0x102);
}

#[test]
fn rsp_vcont_steps_one_ap_and_validates_the_complete_action_list() {
    let mut vm = Running::new(4);
    assert_eq!(vm.packet("vCont;s:2;c:99"), "E01");
    assert_eq!(vm.rax(1), 0x100);
    assert_eq!(vm.rax(2), 0x101);
    assert_eq!(vm.packet("vCont;s:2"), "T05thread:2;core:1;");
    assert_eq!(vm.packet("qC"), "QC2");
    assert_eq!(vm.rax(1), 0x100);
    assert_eq!(vm.rax(2), 0x102);
    assert_eq!(vm.rax(3), 0x102);
    assert_eq!(vm.rax(4), 0x103);
}
#[test]
fn rsp_bad_thread_selection_and_unknown_signal_have_no_target_effect() {
    let mut vm = Running::new(2);
    assert_eq!(vm.rax(2), 0x101);
    for packet in [
        "Hg3",
        "Hc3",
        "Hgp1.2",
        "Hg+1",
        "Hg",
        "vCont;S05:2",
        "vCont;c:1;garbage",
    ] {
        assert_eq!(vm.packet(packet), "E01", "{packet}");
    }
    assert_eq!(vm.packet("qC"), "QC2");
    assert_eq!(vm.packet("T2"), "OK");
    assert_eq!(vm.packet("T3"), "E01");
    assert_eq!(vm.rax(1), 0x100);
    assert_eq!(vm.rax(2), 0x101);
}
#[test]
fn rsp_ap_register_writes_cover_full_and_single_register_packets() {
    let mut vm = Running::new(2);
    assert_eq!(vm.rax(2), 0x101);
    assert_eq!(vm.packet("P0=8877665544332211"), "OK");
    assert_eq!(vm.rax(2), 0x1122_3344_5566_7788);
    assert_eq!(vm.packet("P0=01"), "E01");
    let mut registers = vm.packet("g");
    registers.replace_range(..16, "0807060504030201");
    assert_eq!(vm.packet(&format!("G{registers}")), "OK");
    assert_eq!(vm.rax(2), 0x0102_0304_0506_0708);
    assert_eq!(vm.rax(1), 0x100);
}
#[test]
fn rsp_ap_breakpoint_stops_the_actual_cpu_without_rewriting_guest_code() {
    let mut vm = Running::new(2);
    let address = BSP + 256 + 3;
    assert_eq!(vm.packet(&format!("Z0,{address:x},1")), "OK");
    assert_eq!(vm.packet("c"), "T05thread:2;core:1;");
    assert_eq!(vm.rax(2), 0x102);
    assert_eq!(vm.packet(&format!("m{:x},5", BSP + 256)), "48ffc0ebfb");
    assert_eq!(vm.packet(&format!("z0,{address:x},1")), "OK");
    assert_eq!(vm.packet("vCont;s:2"), "T05thread:2;core:1;");
    assert_eq!(
        vm.rax(2),
        0x102,
        "the branch retires without incrementing RAX"
    );
}

#[test]
fn rsp_x87_state_is_cpu_local_and_top_writes_preserve_physical_registers() {
    let mut vm = Running::new(2);
    assert_eq!(vm.packet("Hg2"), "OK");
    assert_eq!(vm.packet("P18=0123456789abcdefabcd"), "OK");
    assert_eq!(vm.packet("p18"), "0123456789abcdefabcd");
    assert_eq!(vm.packet("P21=00380000"), "OK");
    assert_eq!(
        vm.packet("p19"),
        "0123456789abcdefabcd",
        "new ST1 maps to the former physical ST0"
    );
    assert_eq!(vm.packet("p18"), "00000000000000000000");
    assert_eq!(vm.packet("Hg1"), "OK");
    assert_eq!(vm.packet("p18"), "00000000000000000000");
    assert_eq!(
        vm.packet("p28"),
        "E01",
        "unknown register is not fabricated as zero"
    );
}
#[test]
fn rsp_description_chunks_respect_the_requested_byte_count() {
    let mut vm = Running::new(2);
    let first = vm.packet("qXfer:features:read:target.xml:0,20");
    assert_eq!(first.len(), 33);
    assert!(first.starts_with('m'));
    assert_eq!(vm.packet("qXfer:features:read:target.xml:0,0"), "E01");
    assert_eq!(vm.packet("qXfer:features:read:target.xml:ffffffff,20"), "l");
}

#[path = "gdb_smp_client_tests.rs"]
mod client;

#[test]
fn rsp_reconnect_discards_prior_events_and_restores_selected_step_control() {
    let mut vm = Running::new(2);
    assert_eq!(vm.packet("Hg2"), "OK");
    // Leave an owner-produced event unconsumed, then lose the client connection.
    // The new connection barrier must not mistake it for a query response.
    vm.commands.send(GdbCommand::Step).unwrap();
    vm.stream.take().unwrap().shutdown(Shutdown::Both).unwrap();
    let stream = TcpStream::connect(vm.address).unwrap();
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(30)))
        .unwrap();
    vm.stream = Some(stream);
    assert_eq!(vm.packet("qfThreadInfo"), "m1,2");
    let boot = vm.rax(1);
    assert_eq!(vm.packet("vCont;s:2"), "T05thread:2;core:1;");
    assert_eq!(vm.rax(1), boot, "a new selected step still parks its peer");
}

#[test]
fn rsp_default_action_before_a_specific_action_takes_precedence() {
    let mut vm = Running::new(2);
    let ap = BSP + 256;
    assert_eq!(vm.packet(&format!("M{ap:x},8:48ffc048ffc0ebf8")), "OK");
    assert_eq!(vm.packet(&format!("Z0,{:x},1", ap + 6)), "OK");
    assert_eq!(vm.packet("vCont;c;s:2"), "T05thread:2;core:1;");
    assert_eq!(
        vm.rax(2),
        0x103,
        "the leftmost default continues through two INCs"
    );
    assert!(vm.rax(1) > 0x100, "the default continue also runs the BSP");
}
#[test]
fn rsp_stop_action_reports_its_selected_thread_without_retirement() {
    let mut vm = Running::new(2);
    assert_eq!(vm.packet("vCont;t:2"), "T02thread:2;core:1;");
    assert_eq!(vm.packet("qC"), "QC2");
    assert_eq!(vm.rax(1), 0x100);
    assert_eq!(vm.rax(2), 0x101);
}
