use rax::user::windows::{WindowsConfig, WindowsProcess, memory::Mem, process::RunStatus, layout, context::RegContext, loader::{self,SymRef}};
use rax::isa::arm::decoder::Decoder;
use std::{collections::VecDeque, sync::atomic::AtomicBool};
fn main() {
    for path in std::env::args().skip(1) {
        println!("program {path}");
        let image=std::fs::read(&path).unwrap();
        let mut cfg=WindowsConfig::embedded("C:\\app\\probe.exe",vec![],vec![],4096).unwrap();
        cfg.native_libraries=true;cfg.arena_bytes=268435456;cfg.slice_insns=1;
        let mut process=WindowsProcess::spawn_image(cfg,image).unwrap();
        let p=process.state();let o=layout::offsets(p.arch);
        println!("arch={} PEB={:#x} ProcessHeap={:?} heaps={:?}",p.arch,p.peb,p.space.ptr(p.peb+o.peb_process_heap,o.ptr),p.heaps);
        for m in &p.modules.list {println!("module {} base={:#x} size={:#x} entry={:#x}",m.name,m.base,m.size,m.entry);}
        {
            let p=process.state_mut();let tid=*p.threads.keys().next().unwrap();
            let module=p.modules.list.iter().position(|m|m.name.eq_ignore_ascii_case("ntdll.dll")).unwrap();
            let target=loader::lookup(p,module,&SymRef::Name(b"LdrInitializeThunk".to_vec(),None)).unwrap().unwrap();
            let o=layout::offsets(p.arch);p.space.wptr(p.peb+o.peb_process_heap,o.ptr,0).unwrap();
            let t=p.threads.get_mut(&tid).unwrap();let saved=RegContext::capture(&t.cpu);
            let context=(saved.sp()-0x400)&!15;saved.write(&p.space,context).unwrap();
            t.cpu.set_pc(target);t.cpu.set_sp(context-0x20);t.cpu.set_gpr(0,context);
            t.cpu.set_gpr(1,p.modules.list[module].base);t.cpu.set_gpr(2,0);t.cpu.set_gpr(3,0);
            println!("native LdrInitializeThunk target={target:#x} context={context:#x}");
        }
        let mut history=VecDeque::new();let mut observed_exception=false;let decoder=Decoder::new_aarch64();let cancelled=AtomicBool::new(false);
        for turn in 0..1000000 {
            let p=process.state();
            for (id,t) in &p.threads {
                if !observed_exception && t.frames.iter().any(|f|f.api.name=="KiUserExceptionDispatcher") {
                    println!("first exception appears at turn={turn}");
                    for line in &history {println!("first-fault-history {line}");}
                    for f in &t.frames {if let Some(c)=f.exception_caller.as_ref() {println!("original exception context PC={:#x} SP={:#x}",c.pc(),c.sp());}}
                    observed_exception=true;
                }
                let pc=t.cpu.pc();let bytes=p.space.bytes(pc,4);
                if p.traps.lookup(pc).is_some() {println!("frontier PC={pc:#x} query={:?} trap={:?} frames={:?}",p.vm.query(pc),p.traps.lookup(pc),t.frames.iter().map(|f|(f.api.name,f.entry_sp,f.cursor,f.ret_addr,f.callback_sp,f.cont.is_some())).collect::<Vec<_>>());}
                let insn=bytes.as_ref().ok().map(|b|format!("{:?}",decoder.decode(b)));
                history.push_back(format!("turn={turn} thread={id} PC={pc:#x} SP={:#x} bytes={bytes:02x?} insn={insn:?} registers={:x?}",t.cpu.sp(),(0..t.cpu.gpr_count()).map(|r|t.cpu.gpr(r)).collect::<Vec<_>>()));
                if history.len()>32 {history.pop_front();}
            }
            let result=process.run_slice(1,&cancelled);
            if matches!(result,RunStatus::Complete(_)) {
                for line in history {println!("{line}");}
                println!("terminal turn={turn} {result:?}");break;
            }
            if turn==999999 {println!("diagnostic turn budget exhausted");}
        }
    }
}
