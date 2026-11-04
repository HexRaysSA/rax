// Independent Linux x86-64 KVM runner for the generated MOVSXD reference guest.
// No RAX decoder, planner, CPU adapter or device implementation is linked.
#include <elf.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define RAM_BYTES (64u * 1024u * 1024u)
#define MAX_ELF_BYTES (16u * 1024u * 1024u)
#define MAX_OUTPUT_BYTES (1024u * 1024u)

static void require(int condition, const char *operation)
{
    if (!condition) {
        fprintf(stderr, "native MOVSXD reference: %s failed\n", operation);
        exit(1);
    }
}

static uint32_t load_guest(const char *path, unsigned char *ram)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    require(fd >= 0, "open generated ELF");
    struct stat metadata;
    require(fstat(fd, &metadata) == 0 && S_ISREG(metadata.st_mode), "ELF metadata");
    require(metadata.st_size >= (off_t)sizeof(Elf32_Ehdr) &&
            metadata.st_size <= MAX_ELF_BYTES, "bounded ELF size");
    size_t length = (size_t)metadata.st_size;
    unsigned char *file = mmap(NULL, length, PROT_READ, MAP_PRIVATE, fd, 0);
    require(file != MAP_FAILED, "map generated ELF");
    Elf32_Ehdr header;
    memcpy(&header, file, sizeof(header));
    require(memcmp(header.e_ident, ELFMAG, SELFMAG) == 0 &&
            header.e_ident[EI_CLASS] == ELFCLASS32 &&
            header.e_ident[EI_DATA] == ELFDATA2LSB &&
            header.e_ident[EI_VERSION] == EV_CURRENT &&
            header.e_version == EV_CURRENT && header.e_type == ET_EXEC &&
            header.e_machine == EM_386, "ELF32 little-endian executable identity");
    require(header.e_phentsize == sizeof(Elf32_Phdr) && header.e_phnum > 0 &&
            header.e_phnum <= 64 && header.e_phoff <= length &&
            (size_t)header.e_phnum * sizeof(Elf32_Phdr) <= length - header.e_phoff,
            "program-header bounds");
    int executable_entry = 0;
    for (unsigned int index = 0; index < header.e_phnum; ++index) {
        Elf32_Phdr segment;
        memcpy(&segment, file + header.e_phoff + index * sizeof(segment), sizeof(segment));
        if (segment.p_type != PT_LOAD) {
            continue;
        }
        require(segment.p_paddr == segment.p_vaddr && segment.p_filesz <= segment.p_memsz &&
                segment.p_paddr <= RAM_BYTES && segment.p_memsz <= RAM_BYTES - segment.p_paddr &&
                segment.p_offset <= length && segment.p_filesz <= length - segment.p_offset,
                "identity-loaded segment bounds");
        memset(ram + segment.p_paddr, 0, segment.p_memsz);
        memcpy(ram + segment.p_paddr, file + segment.p_offset, segment.p_filesz);
        if ((segment.p_flags & PF_X) && header.e_entry >= segment.p_paddr &&
            (uint64_t)header.e_entry < (uint64_t)segment.p_paddr + segment.p_memsz) {
            executable_entry = 1;
        }
    }
    require(executable_entry, "entry in executable segment");
    require(munmap(file, length) == 0 && close(fd) == 0, "release ELF input");
    return header.e_entry;
}

static void configure_cpu(int kvm, int cpu, uint32_t entry)
{
    size_t bytes = sizeof(struct kvm_cpuid2) + 256 * sizeof(struct kvm_cpuid_entry2);
    struct kvm_cpuid2 *cpuid = calloc(1, bytes);
    require(cpuid != NULL, "allocate CPUID");
    cpuid->nent = 256;
    require(ioctl(kvm, KVM_GET_SUPPORTED_CPUID, cpuid) == 0, "supported CPUID");
    require(ioctl(cpu, KVM_SET_CPUID2, cpuid) == 0, "install CPUID");
    free(cpuid);
    struct kvm_sregs special;
    require(ioctl(cpu, KVM_GET_SREGS, &special) == 0, "initial system registers");
    // The ELF starts in flat 32-bit protected mode and installs its own GDT,
    // page tables, EFER.LME and 64-bit code segment before the reference cases.
    struct kvm_segment data = {
        .base = 0, .limit = UINT32_MAX, .selector = 16,
        .type = 3, .present = 1, .db = 1, .s = 1, .g = 1,
    };
    special.cs = data;
    special.cs.selector = 8;
    special.cs.type = 11;
    special.ds = special.es = special.ss = special.fs = special.gs = data;
    special.cr0 = 0x60000011;
    special.cr3 = 0;
    special.cr4 = 0;
    special.efer = 0;
    require(ioctl(cpu, KVM_SET_SREGS, &special) == 0, "flat protected-mode seed");
    struct kvm_regs registers = {
        .rip = entry, .rsp = 0x90000, .rflags = 2, .rax = 0x2badb002,
    };
    require(ioctl(cpu, KVM_SET_REGS, &registers) == 0, "initial GPRs");
}

static void collect_records(int cpu, struct kvm_run *run, size_t run_size)
{
    size_t output = 0;
    int completed = 0;
    // The parent also imposes a process watchdog. This alarm belongs only to
    // this owned probe process and uses its default terminating disposition.
    alarm(10);
    for (unsigned int exits = 0; exits < 1000000; ++exits) {
        require(ioctl(cpu, KVM_RUN, 0) == 0, "native guest entry");
        if (run->exit_reason != KVM_EXIT_IO) {
            struct kvm_regs registers;
            require(ioctl(cpu, KVM_GET_REGS, &registers) == 0, "failed-entry diagnostic");
            fprintf(stderr, "unexpected exit %u at RIP 0x%llx\n", run->exit_reason,
                    (unsigned long long)registers.rip);
            exit(1);
        }
        require(run->io.direction == KVM_EXIT_IO_OUT && run->io.count > 0,
                "output-only reference protocol");
        uint64_t length = (uint64_t)run->io.size * run->io.count;
        require(run->io.data_offset <= run_size && length <= run_size - run->io.data_offset,
                "native I/O buffer bounds");
        unsigned char *bytes = (unsigned char *)run + run->io.data_offset;
        if (run->io.port == 0xe9 && run->io.size == 1) {
            require(length <= MAX_OUTPUT_BYTES - output, "bounded record output");
            require(fwrite(bytes, 1, (size_t)length, stdout) == length, "record output");
            output += (size_t)length;
        } else if (run->io.port == 0xf4 && run->io.size == 4 && run->io.count == 1) {
            uint32_t status;
            memcpy(&status, bytes, sizeof(status));
            require(status == 0x10, "guest completion status");
            completed = 1;
            break;
        } else {
            require(0, "recognized reference output port");
        }
    }
    alarm(0);
    require(completed && output > 20 && fflush(stdout) == 0, "complete reference output");
}

int main(int argc, char **argv)
{
    require(argc == 2, "one generated ELF argument");
    int kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    require(kvm >= 0 && ioctl(kvm, KVM_GET_API_VERSION, 0) == KVM_API_VERSION, "KVM API");
    int vm = ioctl(kvm, KVM_CREATE_VM, 0);
    require(vm >= 0, "create native VM");
    unsigned char *ram = mmap(NULL, RAM_BYTES, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    require(ram != MAP_FAILED, "allocate reference RAM");
    uint32_t entry = load_guest(argv[1], ram);
    struct kvm_userspace_memory_region region = {
        .slot = 0, .memory_size = RAM_BYTES, .userspace_addr = (uintptr_t)ram,
    };
    require(ioctl(vm, KVM_SET_USER_MEMORY_REGION, &region) == 0, "register RAM");
    int cpu = ioctl(vm, KVM_CREATE_VCPU, 0);
    require(cpu >= 0, "create native CPU");
    configure_cpu(kvm, cpu, entry);
    int mapping_size = ioctl(kvm, KVM_GET_VCPU_MMAP_SIZE, 0);
    require(mapping_size >= (int)sizeof(struct kvm_run), "run mapping size");
    struct kvm_run *run = mmap(NULL, (size_t)mapping_size, PROT_READ | PROT_WRITE,
                               MAP_SHARED, cpu, 0);
    require(run != MAP_FAILED, "map native run buffer");
    collect_records(cpu, run, (size_t)mapping_size);
    require(munmap(run, (size_t)mapping_size) == 0, "release run mapping");
    require(close(cpu) == 0 && close(vm) == 0, "destroy native VM");
    require(munmap(ram, RAM_BYTES) == 0 && close(kvm) == 0, "release reference RAM and KVM");
    return 0;
}
