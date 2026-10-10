use rax::user::windows::{WindowsConfig, WindowsProcess, memory::Mem, process::RunStatus, layout, loader::{self,SymRef}, context::RegContext};
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
        let (tid,saved,target,resume)={
            let p=process.state_mut();let tid=*p.threads.keys().next().unwrap();
            let module=p.modules.list.iter().position(|m|m.name.eq_ignore_ascii_case("ntdll.dll")).unwrap();
            let target=loader::lookup(p,module,&SymRef::Name(b"RtlCreateHeap".to_vec(),None)).unwrap().unwrap();
            let o=layout::offsets(p.arch);p.space.wptr(p.peb+o.peb_process_heap,o.ptr,0).unwrap();
            let t=p.threads.get_mut(&tid).unwrap();let saved=RegContext::capture(&t.cpu);let resume=p.traps.callback_return();
            println!("native heap target={target:#x} resume={resume:#x}");
            t.cpu.set_pc(target);t.cpu.set_gpr(30,resume);
            for r in 0..6 {t.cpu.set_gpr(r,if r==0 {2} else {0});}
            (tid,saved,target,resume)
        };
        let mut returned_heap=None;
        let mut bootstrap_history=VecDeque::new();let mut heap_exception_seen=false;let bootstrap_decoder=Decoder::new_aarch64();let cancel=AtomicBool::new(false);
        for turn in 0..100000 {
            let p=process.state();let Some(t)=p.threads.get(&tid) else{break;};
            if !heap_exception_seen && t.frames.iter().any(|f|f.api.name=="KiUserExceptionDispatcher") {
                println!("heap first exception at turn={turn}");for line in &bootstrap_history {println!("heap-first-fault {line}");}
                for f in &t.frames {if let Some(c)=f.exception_caller.as_ref(){println!("heap original fault PC={:#x} SP={:#x}",c.pc(),c.sp());}}
                heap_exception_seen=true;
            }
            if t.cpu.pc()==resume && t.frames.is_empty() && t.cpu.sp()==saved.sp() {returned_heap=Some(t.cpu.gpr(0));break;}
            let pc=t.cpu.pc();let bytes=p.space.bytes(pc,4);let insn=bytes.as_ref().ok().map(|b|format!("{:?}",bootstrap_decoder.decode(b)));
            bootstrap_history.push_back(format!("heap turn={turn} PC={pc:#x} SP={:#x} insn={insn:?} registers={:x?}",t.cpu.sp(),(0..t.cpu.gpr_count()).map(|r|t.cpu.gpr(r)).collect::<Vec<_>>()));
            if bootstrap_history.len()>32 {bootstrap_history.pop_front();}
            let result=process.run_slice(1,&cancel);
            if matches!(result,RunStatus::Complete(_)){println!("heap bootstrap terminal {result:?}");break;}
        }
        println!("native RtlCreateHeap return={returned_heap:x?} target={target:#x}");
        for line in bootstrap_history {println!("{line}");}
        let Some(heap)=returned_heap.filter(|h|*h!=0) else {continue;};
        {let p=process.state_mut();let o=layout::offsets(p.arch);p.space.wptr(p.peb+o.peb_process_heap,o.ptr,heap).unwrap();
         let t=p.threads.get_mut(&tid).unwrap();saved.apply(&mut t.cpu).unwrap();}
        println!("resuming ordinary startup with installed RTL heap={heap:#x}");
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
