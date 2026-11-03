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

static int enter(struct machine *m, int immediate, const char *phase) {
    m->run->immediate_exit=immediate;
    errno=0;
    int result=ioctl(m->cpu,KVM_RUN,0), error=errno;
    struct kvm_regs r;
    assert(ioctl(m->cpu,KVM_GET_REGS,&r)==0);
    printf("{\"phase\":\"%s\",\"immediate\":%d,\"result\":%d,\"errno\":%d,\"reason\":%u,\"rip\":%llu,\"rax\":%llu,\"rcx\":%llu,\"rsi\":%llu,\"rdi\":%llu,\"ram3000\":%u,\"rflags\":%llu",
        phase,immediate,result,error,m->run->exit_reason,
        (unsigned long long)r.rip,(unsigned long long)r.rax,
        (unsigned long long)r.rcx,(unsigned long long)r.rsi,
        (unsigned long long)r.rdi,m->ram[0x3000],(unsigned long long)r.rflags);
    if (result==0 && m->run->exit_reason==KVM_EXIT_MMIO)
        printf(",\"mmio_address\":%llu,\"write\":%u,\"len\":%u,\"data0\":%u",
            (unsigned long long)m->run->mmio.phys_addr,m->run->mmio.is_write,
            m->run->mmio.len,m->run->mmio.data[0]);
    puts("}");
    return result==0 ? (int)m->run->exit_reason : -error;
}

int main(void) {
    // IN AL,70; MOV [3000],AL; OUT71,AL; HLT.
    const uint8_t scalar[]={0xe4,0x70,0xa2,0x00,0x30,0xe6,0x71,0xf4};
    struct machine m=create(scalar,sizeof scalar);
    assert(enter(&m,0,"scalar_input")==KVM_EXIT_IO);
    assert(m.run->io.direction==KVM_EXIT_IO_IN && m.run->io.count==1);
    *((uint8_t*)m.run+m.run->io.data_offset)=0x5a;
    assert(enter(&m,1,"scalar_input_drain")==-EINTR);
    assert(m.ram[0x3000]==0);
    assert(enter(&m,0,"scalar_output")==KVM_EXIT_IO);
    assert(m.run->io.direction==KVM_EXIT_IO_OUT && m.run->io.port==0x71);
    assert(*((uint8_t*)m.run+m.run->io.data_offset)==0x5a);
    assert(m.ram[0x3000]==0x5a);
    assert(enter(&m,1,"scalar_output_drain")==-EINTR);
    assert(enter(&m,0,"scalar_halt")==KVM_EXIT_HLT);
    destroy(&m);

    // Address override INC byte [fee00000], a native MMIO read-modify-write.
    const uint8_t rmw[]={0x67,0xfe,0x05,0x00,0x00,0xe0,0xfe,0xf4};
    m=create(rmw,sizeof rmw);
    assert(enter(&m,0,"rmw_read")==KVM_EXIT_MMIO);
    assert(!m.run->mmio.is_write && m.run->mmio.len==1);
    m.run->mmio.data[0]=0x5a;
    int second=enter(&m,1,"rmw_read_drain");
    if (second==KVM_EXIT_MMIO) {
        assert(m.run->mmio.is_write && m.run->mmio.data[0]==0x5b);
        assert(enter(&m,1,"rmw_write_drain")==-EINTR);
    } else {
        assert(second==-EINTR);
        assert(enter(&m,0,"rmw_write")==KVM_EXIT_MMIO);
        assert(m.run->mmio.is_write && m.run->mmio.data[0]==0x5b);
        assert(enter(&m,1,"rmw_write_drain")==-EINTR);
    }
    assert(enter(&m,0,"rmw_halt")==KVM_EXIT_HLT);
    destroy(&m);

    // Complete every kernel REP batch while immediate_exit excludes the next
    // guest instruction. Deliberately cross the native one-page batch limit.
    for (unsigned width=1; width<=4; width*=2) {
        for (unsigned reverse=0; reverse<2; reverse++) {
            uint8_t rep[]={0xf3,0x6c,0xc6,0x06,0x00,0x30,0x99,0xf4};
            uint8_t rep32[]={0x66,0xf3,0x6d,0xc6,0x06,0x00,0x30,0x99,0xf4};
            if (width==2) rep[1]=0x6d;
            m=create(width==4 ? rep32 : rep,width==4 ? sizeof rep32 : sizeof rep);
            struct kvm_regs before;
            assert(ioctl(m.cpu,KVM_GET_REGS,&before)==0);
            before.rflags=2 | (reverse ? 1<<10 : 0);
            before.rdx=0x70; before.rcx=256;
            before.rdi=0x4000+(reverse ? 255*width : 0);
            assert(ioctl(m.cpu,KVM_SET_REGS,&before)==0);
            unsigned transferred=0, batches=0;
            while (transferred<256) {
                assert(enter(&m,0,"rep_input")==KVM_EXIT_IO);
                assert(m.run->io.direction==KVM_EXIT_IO_IN);
                assert(m.run->io.size==width && m.run->io.port==0x70);
                unsigned count=m.run->io.count;
                assert(count && count<=256-transferred);
                memset((uint8_t*)m.run+m.run->io.data_offset,0x5a,width*count);
                assert(enter(&m,1,"rep_input_drain")==-EINTR);
                assert(m.ram[0x3000]==0);
                struct kvm_regs after;
                assert(ioctl(m.cpu,KVM_GET_REGS,&after)==0);
                transferred+=count; batches++;
                assert(after.rcx==256-transferred);
                assert(after.rdi==(uint16_t)(before.rdi+(reverse ? -1 : 1)*(int)(transferred*width)));
            }
            for (unsigned i=0;i<256*width;i++) assert(m.ram[0x4000+i]==0x5a);
            assert(enter(&m,0,"rep_halt")==KVM_EXIT_HLT);
            assert(m.ram[0x3000]==0x99);
            printf("{\"phase\":\"rep_summary\",\"width\":%u,\"df\":%u,\"elements\":%u,\"batches\":%u}\n",
                   width,reverse,transferred,batches);
            destroy(&m);
        }
    }
    return 0;
}
