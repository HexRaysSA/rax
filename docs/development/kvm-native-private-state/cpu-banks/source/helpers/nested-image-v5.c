#define main retained_independent_probe_main
#include "probe.c"
#undef main
int enter_vmx_for_rust(int kvm, int cpu, void *ram) {
    const uint8_t code[]={0xf3,0x0f,0xc7,0x33, // VMXON [RBX].
                          0x66,0x0f,0xc7,0x73,0x08, // VMCLEAR [RBX+8].
                          0x0f,0xc7,0x73,0x08, // VMPTRLD [RBX+8].
                          0x48,0xc7,0xc0,0x1e,0x68,0,0, // RAX=GUEST_RIP field.
                          0x48,0xba,0x48,0x47,0x46,0x45,0x44,0x43,0x42,0x41,
                          0x0f,0x79,0xc2, // VMWRITE RAX,RDX.
                          0x9c,0x58,0xe6,0x80,
                          0x0f,0xc7,0x7b,0x10, // VMPTRST [RBX+16].
                          0x48,0xc7,0xc0,0x1e,0x68,0,0, // RAX=GUEST_RIP field.
                          0x0f,0x78,0xc6, // VMREAD RSI,RAX.
                          0x48,0x89,0x73,0x20, // Store field at RAM[0x6020].
                          0x0f,0x01,0xc4,0x9c,0x58,0xe6,0x81,0xf4};
    struct machine m={.kvm=kvm,.cpu=cpu,.ram=ram};
    memcpy(m.ram+0x1000,code,sizeof code);
    m.run_size=(size_t)ioctl(kvm,KVM_GET_VCPU_MMAP_SIZE,0);
    m.run=mmap(NULL,m.run_size,PROT_READ|PROT_WRITE,MAP_SHARED,cpu,0);
    assert(m.run!=MAP_FAILED);setup(&m);
    assert(enter(&m,0,"rust_source_vmxon")==KVM_EXIT_IO);
    assert(m.run->io.port==0x80);
    struct kvm_regs regs;assert(ioctl(cpu,KVM_GET_REGS,&regs)==0);
    assert((regs.rax&0x41)==0);
    assert(enter(&m,1,"rust_source_output_completion")==-EINTR);
    assert(munmap(m.run,m.run_size)==0);
    return 0;
}

void setup_vmx_for_rust(int kvm, int cpu, void *ram) {
    struct machine m={.kvm=kvm,.cpu=cpu,.ram=ram};
    setup(&m); // Configure controls and page tables without executing VMXON.
}
