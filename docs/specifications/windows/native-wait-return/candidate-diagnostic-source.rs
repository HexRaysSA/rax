use rax::user::windows::arch::{WinArch, WinCpu};
use rax::user::windows::memory::Mem;
use rax::user::windows::objects::Object;
use rax::user::windows::process::{Proc, WindowsConfig, WindowsProcess};
use serde_json::{Value, json};

fn attributes(p: &Proc, address: u64) -> Value {
    if address == 0 {
        return Value::Null;
    }
    let width = p.arch.ptr_size();
    let root = p.space.ptr(address + width, width).ok();
    let descriptor = p.space.ptr(address + 2 * width, width).ok();
    let length = descriptor.and_then(|a| p.space.u16(a).ok());
    let maximum = descriptor.and_then(|a| p.space.u16(a + 2).ok());
    let buffer = descriptor.and_then(|a| p.space.ptr(a + width, width).ok());
    let units = length.zip(buffer).and_then(|(n, a)| {
        if n % 2 != 0 || n > 32766 {
            return None;
        }
        p.space.bytes(a, n as usize).ok().map(|bytes| {
            bytes
                .chunks_exact(2)
                .map(|b| u16::from_le_bytes([b[0], b[1]]))
                .collect::<Vec<_>>()
        })
    });
    json!({"address":format!("{address:#x}"),"length":p.space.u32(address).ok(),
        "root":root,"name_descriptor":descriptor,"flags":p.space.u32(address+3*width).ok(),
        "name_length_bytes":length,"name_maximum_bytes":maximum,"name_buffer":buffer,
        "name_units":units,"name_text":units.as_ref().map(|u|String::from_utf16(u).map_err(|e|e.to_string()))})
}

fn security_descriptor(p: &Proc, address: u64) -> Value {
    if address == 0 {
        return Value::Null;
    }
    let observe = || -> Result<Vec<u8>, String> {
        let header = p.space.bytes(address, 20).map_err(|e| format!("{e:?}"))?;
        let control = u16::from_le_bytes([header[2], header[3]]);
        if control & 0x8000 == 0 {
            return Err("absolute security descriptor requires separate pointer capture".into());
        }
        let mut total = 20usize;
        for (i, pair) in header[4..20].chunks_exact(4).enumerate() {
            let offset = u32::from_le_bytes(pair.try_into().unwrap()) as usize;
            if offset == 0 {
                continue;
            }
            if !(20..4096).contains(&offset) {
                return Err("security descriptor offset outside observer bound".into());
            }
            let at = address
                .checked_add(offset as u64)
                .ok_or("descriptor address overflow")?;
            let prefix = p.space.bytes(at, 8).map_err(|e| format!("{e:?}"))?;
            let bytes = if i < 2 {
                if prefix[1] > 15 {
                    return Err("SID subauthority count outside ABI bound".into());
                }
                8 + usize::from(prefix[1]) * 4
            } else {
                usize::from(u16::from_le_bytes([prefix[2], prefix[3]]))
            };
            if bytes < 8 || offset.checked_add(bytes).is_none_or(|n| n > 4096) {
                return Err("descriptor component outside observer bound".into());
            }
            total = total.max(offset + bytes);
        }
        p.space.bytes(address, total).map_err(|e| format!("{e:?}"))
    };
    json!({"address":address,"capture":observe()})
}

fn main() {
    let program = std::env::args().nth(1).expect("owned fixture path");
    let mut config = WindowsConfig::new(&program, vec![]);
    config.native_libraries = true;
    config.arena_bytes = 512 << 20;
    config.slice_insns = 1 << 20;
    let trace_path = std::path::Path::new(&program).parent().unwrap().join("shutdown-instructions.txt");
    config.drives = rax::user::windows::fs::DriveMap::from_host().expect("host drive discovery");
    let mut process = match WindowsProcess::spawn(config) {
        Ok(process) => process,
        Err(error) => {
            println!(
                "{}",
                json!({"schema":"rax-windows29704-frontier-v1","stage":"spawn-error","error":format!("{error:?}")})
            );
            return;
        }
    };
    let cancel = std::sync::atomic::AtomicBool::new(false);
    let mut turns = 0u64;
    let terminal = loop {
        if turns >= 788 {
            use std::io::Write;
            let p = process.state();
            let threads: Vec<_> = p.threads.values().map(|t|json!({
                "tid":t.tid,"pc":t.cpu.pc(),"sp":t.cpu.sp(),"attached":t.attached,
                "state":format!("{:?}",t.state),"suspended":t.suspend,
                "logical_arch":format!("{:?}",t.cpu.arch()),"gpr":(0..t.cpu.gpr_count()).map(|i|t.cpu.gpr(i)).collect::<Vec<_>>(),
                "module":p.modules.by_address(t.cpu.pc()).map(|(_,m)|json!({"name":m.name,"base":m.base})),
                "bytes":p.space.bytes(t.cpu.pc().saturating_sub(16),64).ok()
            })).collect();
            println!("STATE {}",json!({"turn":turns,"threads":threads}));
            std::io::stdout().flush().unwrap();
        }
        if turns == 900 { break String::from("DiagnosticBudgetExhausted"); }
        if turns == 790 { rax::user::trace::init(&trace_path).unwrap(); }
        turns += 1;
        match process.run_slice(1,&cancel) {
            rax::user::windows::process::RunStatus::Complete(status) => break format!("{status:?}"),
            rax::user::windows::process::RunStatus::Blocked => std::thread::sleep(std::time::Duration::from_millis(1)),
            _ => {}
        }
    };
    rax::user::trace::close();
    let trace = std::fs::read_to_string(&trace_path).unwrap_or_default();
    let p = process.state();
    let wait_objects: Vec<_> = p.objects.iter().filter_map(|(id,obj)|match obj {Object::Event{manual,signaled}=>Some(json!({"id":id,"kind":"Event","manual":manual,"signaled":signaled})),Object::Thread{tid,exit_code}=>Some(json!({"id":id,"kind":"Thread","tid":tid,"exit_code":exit_code})),Object::Mutex{owner,count,abandoned}=>Some(json!({"id":id,"kind":"Mutex","owner":owner,"count":count,"abandoned":abandoned})),_=>None}).collect();
    let threads: Vec<_> = p.threads.values().map(|t| {
        let pc=t.cpu.pc();
        let region = format!("{:?}", p.vm.query(pc));
        let owner = p.modules.by_address(pc).map(|(_, m)| json!({
            "name":m.name,"base":m.base,"size":m.size,"path":m.path}));
        let nearby = p.space.bytes(pc.saturating_sub(16), 96).ok();

        let sp=t.cpu.sp();
        let instruction=p.space.u32(pc.saturating_sub(4)).ok();
        let svc=instruction.is_some_and(|v|v&0xffe0001f==0xd4000001);
        let ec=matches!(&t.cpu,WinCpu::Arm64Ec(_));
        let wrapper=p.space.bytes(pc.saturating_sub(20),52).ok();
        let guarded=svc&&ec&&wrapper.as_ref().is_some_and(|b|{
            let words:Vec<_>=b.chunks_exact(4).map(|b|u32::from_le_bytes(b.try_into().unwrap())).collect();
            words[0]==0xd10043ff&&words[3]==0xf90003f0&&words[5]==0xf94003e9
                &&words[8]==0xeb090210&&words[9]==0x910043ff&&words[11]==0xd2800009&&words[12]==0xd65f03c0
        });
        let argument_sp=sp.checked_add(if guarded{16}else{0}).expect("argument stack extent");
        let fx=t.cpu.x86().map(|cpu|cpu.vcpu().xsave_image(3).bytes);
        let x87_word=|slot:usize|fx.as_ref().map(|b|u64::from_le_bytes(b[32+slot*16..40+slot*16].try_into().unwrap()));
        let arguments:Vec<Option<u64>>=(0..11).map(|i|match p.arch{
            WinArch::Arm64 if i<8=>Some(t.cpu.gpr(i)),
            WinArch::Arm64=>p.space.u64(argument_sp+(i-8)as u64*8).ok(),
            WinArch::X64 if ec&&svc=>match i{
                0..=5=>Some(t.cpu.gpr([1,2,8,9,10,11][i])),
                6=>x87_word(1),7=>x87_word(2),
                _=>p.space.u64(argument_sp+(i-8)as u64*8).ok(),
            },
            WinArch::X64 if i<4=>Some(t.cpu.gpr([10,2,8,9][i])),
            WinArch::X64=>p.space.u64(argument_sp+8+i as u64*8).ok(),
            WinArch::X86=>p.space.ptr(sp+8+i as u64*4,4).ok(),
        }).collect();
        let preview=|index:usize,bytes:usize|arguments[index].filter(|a|*a!=0).map(|a|{
            json!({"address":a,"bytes":p.space.bytes(a,bytes).ok()})
        });
        let port = arguments[0].and_then(|handle| match p.objects.get(handle) {
            Some(Object::LpcPort(port)) => Some(format!("{port:?}")),
            _ => None,
        });
        let sent = arguments[3].filter(|base| *base != 0).and_then(|base| p.space.u64(base + 48).ok());
        let sent_file = sent.and_then(|handle| match p.objects.get(handle) {
            Some(Object::File(file)) => Some(json!({
                "path": file.path, "host_path": file.host_path, "retained": file.host.is_some(),
                "grant": p.objects.access(handle), "identity": format!("{:?}", file.lifetime.identity),
            })),
            _ => None,
        });
        json!({"port":port, "port_handle":arguments[0], "file_handle":sent, "file":sent_file,
            "send_attributes":preview(3,64), "receive_attributes":preview(6,64), "tid":t.tid,"architecture":p.arch.to_string(),"arm64ec":ec,"svc":svc,
            "pc":pc,"pc_region":region,"pc_allocation":p.vm.allocation(pc).map(|a|json!({"base":a.base,"size":a.size,"name":a.name.as_deref()})),"pc_module":owner,"pc_nearby_bytes":nearby,"sp":sp,"argument_sp":argument_sp,"guarded_wrapper":guarded,
            "wrapper_bytes":wrapper,"logical_arch":format!("{:?}",t.cpu.arch()),"gpr":(0..t.cpu.gpr_count()).map(|i|t.cpu.gpr(i)).collect::<Vec<_>>(),
            "stack_bytes":p.space.bytes(sp,160).ok(),"arguments":arguments,
            "connection_attributes":arguments[1].map(|a|attributes(p,a)),
            "client_attributes":arguments[2].map(|a|attributes(p,a)),
            "port_attributes":preview(3,72),"server_security":arguments[5].map(|a|security_descriptor(p,a)),
            "message":preview(6,128),"length":arguments[7].filter(|a|*a!=0).and_then(|a|p.space.ptr(a,p.arch.ptr_size()).ok()),
            "send_message":preview(2,128),"out_attributes":preview(8,64),"in_attributes":preview(9,64),"timeout":preview(10,8)})
    }).collect();
    println!(
        "{}",
        json!({"schema":"rax-windows29704-frontier-v1","terminal":terminal,"threads":threads,"wait_objects":wait_objects,"trace":trace})
    );
}
