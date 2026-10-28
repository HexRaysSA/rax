use std::sync::Arc;
use rax::isa::x86_64::X86_64Vcpu;
use rax::vm::memory::FlatTranslation;
use rax::vm::vcpu::{VCpu,CpuState};
use rax::error::{GuestMemoryFault,MemoryAccessKind};
use vm_memory::{Bytes,GuestAddress,GuestMemoryMmap};
struct Identity;
impl FlatTranslation for Identity {fn translate(&self,a:u64,_:MemoryAccessKind)->Result<u64,GuestMemoryFault>{Ok(a)}}
fn main(){
 let memory=Arc::new(GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0),0x10000)]).unwrap());
 memory.write_slice(&[0x0f,0x05],GuestAddress(0x100)).unwrap();
 let mut cpu=X86_64Vcpu::new(0,memory);
 cpu.enable_user_mode(Arc::new(Identity));let CpuState::X86_64(mut state)=cpu.get_state().unwrap() else {panic!()};state.regs.rip=0x100;cpu.set_state(&CpuState::X86_64(state)).unwrap();
 let exit=cpu.step_with_faults().unwrap();println!("exit={exit:?} count={}",cpu.instruction_count());
 let raw=cpu.save_context().unwrap();assert!(raw.starts_with(b"RAXX8601"));
 std::fs::write(std::env::args().nth(1).unwrap(),raw).unwrap();
}
