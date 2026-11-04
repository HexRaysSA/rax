// Independent native KVM completion-frontier probe, Linux x86-64 only.
// Uses the installed public Linux KVM UAPI, no RAX code or guest OS.
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

struct machine {
    int kvm, vm, cpu;
    size_t run_size;
    uint8_t *ram;
    struct kvm_run *run;
};

static struct machine create(const uint8_t *code, size_t code_size) {
    struct machine m = {0};
    m.kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    assert(m.kvm >= 0 && ioctl(m.kvm, KVM_GET_API_VERSION, 0) == 12);
    m.vm = ioctl(m.kvm, KVM_CREATE_VM, 0);
    assert(m.vm >= 0);
    m.ram = mmap(NULL, 2*1024*1024, PROT_READ|PROT_WRITE,
                 MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    assert(m.ram != MAP_FAILED);
    struct kvm_userspace_memory_region slot = {
        .slot=0, .guest_phys_addr=0, .memory_size=2*1024*1024,
        .userspace_addr=(uintptr_t)m.ram,
    };
    assert(ioctl(m.vm, KVM_SET_USER_MEMORY_REGION, &slot) == 0);
    memcpy(m.ram+0x1000, code, code_size);
    m.cpu = ioctl(m.vm, KVM_CREATE_VCPU, 0);
    assert(m.cpu >= 0);
    m.run_size = ioctl(m.kvm, KVM_GET_VCPU_MMAP_SIZE, 0);
    assert(m.run_size >= sizeof(struct kvm_run));
    m.run = mmap(NULL,m.run_size,PROT_READ|PROT_WRITE,MAP_SHARED,m.cpu,0);
    assert(m.run != MAP_FAILED);
    struct kvm_sregs s;
    assert(ioctl(m.cpu,KVM_GET_SREGS,&s)==0);
    s.cs.base=0; s.cs.selector=0;
    s.ds.base=0; s.ds.selector=0; s.ds.limit=UINT32_MAX; s.ds.g=1;
    s.es.base=0; s.es.selector=0; s.es.limit=UINT32_MAX; s.es.g=1;
    assert(ioctl(m.cpu,KVM_SET_SREGS,&s)==0);
    struct kvm_regs r = {.rip=0x1000,.rflags=2,.rax=0x11};
    assert(ioctl(m.cpu,KVM_SET_REGS,&r)==0);
    return m;
}

static void destroy(struct machine *m) {
    assert(munmap(m->run,m->run_size)==0);
    assert(close(m->cpu)==0);
    assert(close(m->vm)==0);
    assert(munmap(m->ram,2*1024*1024)==0);
    assert(close(m->kvm)==0);
}


static uint64_t read_msr(int fd, uint32_t index) {
    struct kvm_msrs *msrs=calloc(1,sizeof(*msrs)+sizeof(struct kvm_msr_entry));
    assert(msrs); msrs->nmsrs=1;msrs->entries[0].index=index;
    assert(ioctl(fd,KVM_GET_MSRS,msrs)==1);
    uint64_t value=msrs->entries[0].data;free(msrs);return value;
}

static void write_msr(int fd, uint32_t index, uint64_t value) {
    struct kvm_msrs *msrs=calloc(1,sizeof(*msrs)+sizeof(struct kvm_msr_entry));
    assert(msrs);msrs->nmsrs=1;msrs->entries[0].index=index;msrs->entries[0].data=value;
    assert(ioctl(fd,KVM_SET_MSRS,msrs)==1);free(msrs);
}

static void setup(struct machine *m) {
    size_t cpuid_size=sizeof(struct kvm_cpuid2)+256*sizeof(struct kvm_cpuid_entry2);
    struct kvm_cpuid2 *cpuid=calloc(1,cpuid_size);assert(cpuid);cpuid->nent=256;
    assert(ioctl(m->kvm,KVM_GET_SUPPORTED_CPUID,cpuid)==0);
    int vmx=0;
    for(unsigned i=0;i<cpuid->nent;i++)
        if(cpuid->entries[i].function==1) vmx=!!(cpuid->entries[i].ecx&(1u<<5));
    assert(vmx);assert(ioctl(m->cpu,KVM_SET_CPUID2,cpuid)==0);free(cpuid);
    write_msr(m->cpu,0x3a,5); // IA32_FEATURE_CONTROL: locked, VMX outside SMX.
    uint64_t basic=read_msr(m->cpu,0x480);
    uint64_t cr0_fixed0=read_msr(m->cpu,0x486),cr0_fixed1=read_msr(m->cpu,0x487);
    uint64_t cr4_fixed0=read_msr(m->cpu,0x488),cr4_fixed1=read_msr(m->cpu,0x489);
    ((uint64_t*)(m->ram+0x2000))[0]=0x3003;
    ((uint64_t*)(m->ram+0x3000))[0]=0x4003;
    ((uint64_t*)(m->ram+0x4000))[0]=0x83;
    ((uint64_t*)(m->ram+0x5000))[1]=0x00af9b000000ffffULL;
    ((uint64_t*)(m->ram+0x5000))[2]=0x00cf93000000ffffULL;
    *(uint64_t*)(m->ram+0x6000)=0x8000;
    *(uint64_t*)(m->ram+0x6008)=0x9000;
    *(uint64_t*)(m->ram+0x6010)=0xdeadbeef;
    *(uint32_t*)(m->ram+0x8000)=(uint32_t)basic&0x7fffffff;
    *(uint32_t*)(m->ram+0x9000)=(uint32_t)basic&0x7fffffff;
    struct kvm_sregs s;assert(ioctl(m->cpu,KVM_GET_SREGS,&s)==0);
    s.cr0=(cr0_fixed0|0x80010021ULL)&cr0_fixed1;
    s.cr4=(cr4_fixed0|(1u<<5)|(1u<<13))&cr4_fixed1;
    s.cr3=0x2000;s.efer=0x500;s.gdt.base=0x5000;s.gdt.limit=23;
    s.cs=(struct kvm_segment){.base=0,.limit=UINT32_MAX,.selector=8,.type=11,.present=1,.s=1,.l=1,.g=1};
    s.ds=(struct kvm_segment){.base=0,.limit=UINT32_MAX,.selector=16,.type=3,.present=1,.s=1,.db=1,.g=1};
    s.es=s.ds;s.fs=s.ds;s.gs=s.ds;s.ss=s.ds;
    assert(ioctl(m->cpu,KVM_SET_SREGS,&s)==0);
    struct kvm_regs regs={.rip=0x1000,.rflags=2,.rbx=0x6000,.rsp=0x10000};
    assert(ioctl(m->cpu,KVM_SET_REGS,&regs)==0);
    struct kvm_mp_state mp={.mp_state=KVM_MP_STATE_RUNNABLE};
    assert(ioctl(m->cpu,KVM_SET_MP_STATE,&mp)==0);
    printf("{\"phase\":\"setup\",\"vmx_basic\":%llu,\"cr0_fixed0\":%llu,\"cr4_fixed0\":%llu}\n",
           (unsigned long long)basic,(unsigned long long)cr0_fixed0,(unsigned long long)cr4_fixed0);
}

static int enter(struct machine *m, int immediate, const char *phase) {
    m->run->immediate_exit=immediate;errno=0;
    int result=ioctl(m->cpu,KVM_RUN,0),error=errno;
    struct kvm_regs regs;assert(ioctl(m->cpu,KVM_GET_REGS,&regs)==0);
    printf("{\"phase\":\"%s\",\"result\":%d,\"errno\":%d,\"reason\":%u,\"rip\":%llu,\"rax\":%llu,\"port\":%u}\n",
           phase,result,error,m->run->exit_reason,(unsigned long long)regs.rip,
           (unsigned long long)regs.rax,m->run->exit_reason==KVM_EXIT_IO ? m->run->io.port : 0);
    return result==0 ? (int)m->run->exit_reason : -error;
}

int main(void) {
    setvbuf(stdout,NULL,_IOLBF,0);
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
    struct machine source=create(code,sizeof code);setup(&source);
    int capacity=ioctl(source.kvm,KVM_CHECK_EXTENSION,KVM_CAP_NESTED_STATE);
    assert(capacity>=(int)sizeof(struct kvm_nested_state));
    assert(enter(&source,0,"source_vmxon")==KVM_EXIT_IO);
    assert(source.run->io.port==0x80);
    struct kvm_regs regs;assert(ioctl(source.cpu,KVM_GET_REGS,&regs)==0);
    assert((regs.rax&0x41)==0); // VMXON completed with CF=ZF=0.
    assert(enter(&source,1,"source_output_completion")==-EINTR);
    struct kvm_sregs sregs;struct kvm_vcpu_events events;struct kvm_mp_state mp;
    assert(ioctl(source.cpu,KVM_GET_REGS,&regs)==0);
    assert(ioctl(source.cpu,KVM_GET_SREGS,&sregs)==0);
    assert(ioctl(source.cpu,KVM_GET_VCPU_EVENTS,&events)==0);
    assert(ioctl(source.cpu,KVM_GET_MP_STATE,&mp)==0);
    struct kvm_nested_state *nested=calloc(1,(size_t)capacity);assert(nested);
    nested->size=(uint32_t)capacity;assert(ioctl(source.cpu,KVM_GET_NESTED_STATE,nested)==0);
    printf("{\"phase\":\"captured\",\"capacity\":%d,\"size\":%u,\"format\":%u,\"flags\":%u,\"vmxon_pa\":%llu,\"vmcs12_pa\":%llu}\n",
           capacity,nested->size,nested->format,nested->flags,
           (unsigned long long)nested->hdr.vmx.vmxon_pa,(unsigned long long)nested->hdr.vmx.vmcs12_pa);
    assert(nested->format==0 && nested->hdr.vmx.vmxon_pa==0x8000);
    assert(nested->size==4224 && nested->hdr.vmx.vmcs12_pa==0x9000);
    uint8_t *ram=malloc(2*1024*1024);assert(ram);memcpy(ram,source.ram,2*1024*1024);
    destroy(&source); // No source VM, vCPU, mapped run or guest backing survives.
    for(int restore_nested=0;restore_nested<=1;restore_nested++) {
        struct machine target=create(code,sizeof code);setup(&target);
        memcpy(target.ram,ram,2*1024*1024);
        assert(ioctl(target.cpu,KVM_SET_SREGS,&sregs)==0);
        assert(ioctl(target.cpu,KVM_SET_REGS,&regs)==0);
        assert(ioctl(target.cpu,KVM_SET_VCPU_EVENTS,&events)==0);
        assert(ioctl(target.cpu,KVM_SET_MP_STATE,&mp)==0);
        if(restore_nested) assert(ioctl(target.cpu,KVM_SET_NESTED_STATE,nested)==0);
        int reason=enter(&target,0,restore_nested ? "private_restore_vmxoff" : "public_only_vmxoff");
        if(restore_nested) {
            assert(reason==KVM_EXIT_IO && target.run->io.port==0x81);
            struct kvm_regs after;assert(ioctl(target.cpu,KVM_GET_REGS,&after)==0);
            assert((after.rax&0x41)==0);
            assert(*(uint64_t*)(target.ram+0x6010)==0x9000);
            assert(*(uint64_t*)(target.ram+0x6020)==0x4142434445464748ULL);
            assert(enter(&target,1,"private_output_completion")==-EINTR);
            assert(enter(&target,0,"private_halt")==KVM_EXIT_HLT);
        } else assert(reason==KVM_EXIT_SHUTDOWN);
        destroy(&target);
    }
    free(ram);free(nested);puts("{\"phase\":\"complete\",\"source_free_private_restore\":true}");
    return 0;
}
