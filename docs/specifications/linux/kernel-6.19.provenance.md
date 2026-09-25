# Linux 6.19 kernel sources provenance

- Canonical title: Linux kernel source tree, selected files
- Issuing organization: the Linux kernel project
- Revision: tag `v6.19`
- Source URL: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git
  (tag `v6.19`); files were retrieved from the GitHub mirror
  `https://raw.githubusercontent.com/torvalds/linux/v6.19/<path>`, which serves
  the same tagged tree; `fs/namei.c`, `fs/utimes.c`, `fs/xattr.c`,
  `fs/sync.c`, `kernel/groups.c`, `mm/readahead.c`,
  `include/linux/xattr.h`, `drivers/perf/riscv_pmu_sbi.c`, `fs/locks.c`,
  `fs/fcntl.c`, `net/netlink/af_netlink.c`, `net/core/rtnetlink.c`,
  `net/ipv4/devinet.c`, `net/ipv6/addrconf.c`, `net/core/dev.c`,
  `net/core/dev_ioctl.c`, the `ipc/` files, `include/linux/ipc.h`,
  `include/linux/ipc_namespace.h`, `kernel/seccomp.c`,
  `net/core/filter.c`, `include/asm-generic/seccomp.h`,
  `arch/x86/include/asm/seccomp.h`, `arch/{x86,arm64,riscv}/include/asm/syscall.h`,
  `arch/riscv/kernel/traps.c`, the `fs/notify/` files,
  `include/linux/{fsnotify,fsnotify_backend}.h`, `fs/open.c`,
  `fs/file_table.c`, `fs/read_write.c`, `fs/attr.c`, `fs/readdir.c`,
  `fs/splice.c`, `arch/x86/entry/syscall_64.c`, `arch/arm64/kernel/syscall.c`,
  `ipc/msgutil.c`, and the machine-administration, clock-setting, and mount
  files (`mm/swapfile.c`, `kernel/reboot.c`, `kernel/acct.c`,
  `arch/x86/kernel/ioport.c`, `kernel/module/main.c`,
  `kernel/printk/printk.c`, `init/Kconfig`, `security/commoncap.c`,
  `kernel/time/{ntp,timekeeping,posix-clock}.c`, `fs/namespace.c`,
  `fs/fsopen.c`, `include/linux/{security,swap,syslog,timex,time64,jiffies,moduleparam,file}.h`,
  `include/asm-generic/param.h`, `include/uapi/asm-generic/param.h`, and
  `include/uapi/linux/{mount,reboot,timex,module}.h`), and the POSIX message
  queue files (`ipc/mqueue.c`, `ipc/mq_sysctl.c`,
  `include/linux/{msg,rbtree_types}.h`, `include/uapi/linux/mqueue.h`),
  and the scheduling-attribute files (`kernel/sched/{core,fair,deadline,rt}.c`,
  `kernel/sched/sched.h`, `include/linux/sched/{prio,rt,deadline}.h`,
  `include/uapi/linux/sched.h`, `include/uapi/linux/sched/types.h`,
  `block/{ioprio,blk-ioc}.c`, `include/linux/ioprio.h`,
  `include/uapi/linux/ioprio.h`), and the process-memory and
  kernel-object comparison files (`mm/{process_vm_access,gup}.c`,
  `kernel/{kcmp,ptrace}.c`, `lib/iov_iter.c`, `include/linux/ptrace.h`,
  `include/uapi/linux/kcmp.h`), and the memory locking and sealing files
  (`mm/{mlock,mseal}.c`, `include/linux/mm.h`,
  `include/uapi/asm-generic/{mman,mman-common}.h`), and the restartable
  sequences files (`kernel/rseq.c`, `include/linux/{rseq,rseq_entry,rseq_types}.h`,
  `include/uapi/linux/rseq.h`, `arch/{arm64,x86,riscv}/Kconfig`) came from kernel.org's
  `https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/<path>?h=v6.19`
  (byte-identical to the mirror for the files compared).
- Retrieved: 24 September 2026 (`drivers/perf/riscv_pmu_sbi.c`,
  `fs/locks.c`, `fs/fcntl.c`, the seven `net/` files above, the System V
  IPC files, the seccomp, file-system notification, and system-call entry
  files, `ipc/msgutil.c`, the machine-administration, clock-setting, and
  mount files, the POSIX message queue files, the scheduling-attribute
  files, the process-memory and kernel-object comparison files, the
  memory locking and sealing files, and the restartable sequences files:
  25 September 2026)
- Integrity: `kernel-6.19.sha256` lists the SHA-256 of every imported file,
  relative to `kernel-6.19/`.
- License: the files carry an SPDX identifier: `GPL-2.0` (103 files),
  `GPL-2.0-only` (51), `GPL-2.0-or-later` (36),
  `GPL-2.0 WITH Linux-syscall-note` (9), `GPL-2.0+` (3),
  `GPL-2.0+ WITH Linux-syscall-note` (2),
  `LGPL-2.1+ WITH Linux-syscall-note` (1, `include/uapi/linux/mqueue.h`),
  or `GPL-1.0+` (1). Seven have none: `mm/memfd.c`, `mm/shmem.c`, and
  `ipc/mqueue.c` state "This file is released under the GPL." in their
  headers; `include/linux/security.h`
  grants the GPL, version 2 or later, in its header;
  `include/linux/timex.h` and `include/uapi/linux/timex.h` carry David L.
  Mills's 1993 permission notice (University of Delaware) ahead of the
  kernel's changes; and `include/uapi/linux/mount.h` states no license,
  so the kernel's `COPYING` applies (GPL-2.0, with the Linux-syscall-note
  for UAPI headers). The license texts are the kernel tree's
  `LICENSES/preferred/GPL-2.0`, `LICENSES/preferred/LGPL-2.1`,
  `LICENSES/deprecated/GPL-1.0`, and
  `LICENSES/exceptions/Linux-syscall-note`. The files are reference material for an
  independent implementation; no RAX source is derived from their text.

Paths under `kernel-6.19/` mirror the kernel tree. The files are reference
inputs; do not reformat or edit them. To move to a newer kernel, import a
complete new `kernel-<version>/` tree with its own provenance record.

## Use in RAX

The `rax-user` Linux personality (`src/user/linux/`) implements the Linux
system-call ABI for emulated user-space programs. These files define the
behavior it reproduces beyond what the UAPI headers
(`uapi-6.19.provenance.md`) specify:

| Area | Files |
|---|---|
| `execve` loading, initial stack, auxiliary vector, `#!` scripts | `fs/binfmt_elf.c`, `fs/binfmt_script.c`, `fs/exec.c`, `arch/{x86,arm64,riscv}/include/asm/elf.h` |
| Address-space layout | `mm/util.c` (`mmap_base`), `arch/x86/mm/mmap.c`, `arch/x86/include/asm/page_64_types.h`, `arch/arm64/include/asm/processor.h`, `arch/riscv/include/asm/{processor,pgtable}.h` |
| Memory-management system calls | `mm/mmap.c`, `mm/vma.c`, `mm/mprotect.c`, `mm/madvise.c`, `mm/mremap.c`, `arch/arm64/include/asm/mman.h` |
| Signal generation, queueing, and delivery | `kernel/signal.c`, `include/linux/signal.h`, `include/linux/signal_types.h`, `include/linux/sched/signal.h`, `kernel/entry/common.c`, `include/linux/entry-common.h` |
| Signal frames and `rt_sigreturn` | `arch/x86/kernel/signal.c`, `arch/x86/kernel/signal_64.c`, `arch/x86/kernel/fpu/{signal.c,core.c,xstate.c,xstate.h}`, `arch/x86/include/asm/sighandling.h`, `arch/x86/include/asm/fpu/{signal.h,types.h,xstate.h}`, `arch/arm64/kernel/signal.c`, `arch/arm64/kernel/ptrace.c`, `arch/arm64/include/asm/ptrace.h`, `arch/arm64/kernel/vdso/sigreturn.S`, `arch/riscv/kernel/signal.c`, `arch/riscv/kernel/vdso/rt_sigreturn.S` |
| Sleeping, timers, and restarts | `kernel/time/hrtimer.c`, `kernel/time/itimer.c`, `kernel/time/posix-timers.{c,h}`, `include/linux/posix-timers.h`, `kernel/time/posix-cpu-timers.c`, `kernel/time/alarmtimer.c`, `kernel/time/time.c`, `include/linux/restart_block.h` |
| Timer, event, and signal descriptors | `fs/timerfd.c`, `fs/eventfd.c`, `fs/signalfd.c`, `fs/anon_inodes.c`, `fs/libfs.c` (`alloc_anon_inode`), `include/linux/{eventfd,timerfd}.h` (flag sets) |
| `epoll` | `fs/eventpoll.c` |
| pidfds | `kernel/pid.c` (`pidfd_open`, `pidfd_getfd`), `fs/pidfs.c` (poll, `PIDFD_GET_INFO`, the file's name and inode), `include/linux/pidfs.h`, `kernel/fork.c` (`pidfd_prepare`, `CLONE_PIDFD`), `kernel/signal.c` (`pidfd_send_signal`), `kernel/exit.c` (`waitid` with `P_PIDFD`), `include/linux/fs.h` (`extensible_ioctl_valid`), `include/linux/uaccess.h` (`copy_struct_to_user`) |
| `/proc/<pid>/fdinfo` | `fs/proc/fd.c` (`seq_show`), with the `show_fdinfo` operations of `fs/pidfs.c`, `fs/eventfd.c`, `fs/timerfd.c`, `fs/signalfd.c`, and `fs/eventpoll.c`, and `fs/proc/array.c` (`render_sigset_t`) |
| `memfd_create` and file seals | `mm/memfd.c`, `include/linux/memfd.h`, `mm/shmem.c` (where seals are enforced: `shmem_setattr`, `shmem_fallocate`, `shmem_file_write_iter`, `shmem_mmap`) |
| Sockets | `net/socket.c`, `net/unix/af_unix.c`, `net/core/sock.c`, `net/core/scm.c`, `net/ipv4/af_inet.c`, `net/ipv6/af_inet6.c`, `include/linux/socket.h`, `include/net/sock.h` |
| Blocking I/O, `poll`, and `select` | `fs/select.c`, `fs/pipe.c`, `drivers/tty/n_tty.c` |
| Threads: creation, exit, and scheduling | `kernel/fork.c`, `kernel/exit.c`, `include/linux/sched/task.h`, `kernel/sched/syscalls.c` (`sched_yield`), `arch/x86/kernel/{process.c,process_64.c}`, `arch/arm64/kernel/process.c`, `arch/riscv/kernel/process.c` (`copy_thread`) |
| Futexes and robust lists | `kernel/futex/{core.c,futex.h,syscalls.c,waitwake.c,requeue.c,pi.c}` |
| Process attributes | `kernel/sys.c`, `kernel/exec_domain.c` (`personality`) |
| Synthesized `/proc` | `fs/proc/base.c`, `fs/proc/array.c`, `fs/proc/task_mmu.c` |
| File creation and times | `fs/namei.c` (`do_mknodat`, `may_mknod`, `vfs_mknod`), `fs/utimes.c` (`utimensat`, `utimes`, `futimesat`, `utime`) |
| Extended attributes | `fs/xattr.c` (name import, the namespaces' permissions, the `*xattr` and `*xattrat` calls), `include/linux/xattr.h` |
| RISC-V user counter access (`scounteren`: only `time`, so `rdcycle` and `rdinstret` raise `SIGILL` unless a perf event is mapped) | `drivers/perf/riscv_pmu_sbi.c` (`sysctl_perf_user_access`, `pmu_sbi_starting_cpu`) |
| File locks | `fs/locks.c` (`flock`, `fcntl_getlk`, `fcntl_setlk`, `flock64_to_posix_lock`, `flock_lock_inode`, `locks_remove_posix`), `fs/fcntl.c` (`do_fcntl`, `check_fcntl_cmd`) |
| Netlink route sockets | `net/netlink/af_netlink.c` (`netlink_create`, `netlink_bind`, `netlink_autobind`, `netlink_connect`, `netlink_getname`, `netlink_sendmsg`, `netlink_recvmsg`, `netlink_dump`, `netlink_ack`, `netlink_rcv_skb`, `netlink_setsockopt`, `netlink_getsockopt`), `net/core/rtnetlink.c` (`rtnetlink_rcv_msg`, `rtnl_dumpit`, `rtnl_dump_all`, `rtnl_getlink`, `rtnl_fill_ifinfo`, `rtnetlink_bind`), `net/ipv4/devinet.c` (`inet_fill_ifaddr`, `inet_set_ifa`), `net/ipv6/addrconf.c` (`inet6_fill_ifaddr`, `inet6_rtm_getaddr`, `ipv6_link_dev_addr`) |
| Interface requests | `net/socket.c` (`sock_ioctl`, `sock_do_ioctl`, `get_user_ifreq`), `net/core/dev_ioctl.c` (`dev_ioctl`, `dev_ifconf`, `dev_ifname`, `dev_ifsioc_locked`, `dev_getifmap`), `net/core/dev.c` (`netdev_get_name`, `netdev_copy_name`, `netif_get_mac_address`, `netif_get_flags`), `net/ipv4/af_inet.c` (`inet_ioctl`), `net/ipv4/devinet.c` (`devinet_ioctl`, `inet_gifconf`), `net/ipv6/af_inet6.c` (`inet6_ioctl`), `net/ipv6/addrconf.c` (`addrconf_add_ifaddr`, `addrconf_del_ifaddr`, `addrconf_set_dstaddr`) |
| System V IPC | `ipc/util.c` (`ipcget`, `ipcget_public`, `ipc_addid`, `ipc_idr_alloc`, `ipcperms`, `ipcctl_obtain_check`, `ipc_update_perm`, `kernel_to_ipc64_perm`), `ipc/util.h` (identifier layout), `ipc/shm.c` (`newseg`, `do_shmat`, `ksys_shmdt`, `ksys_shmctl`, `shm_may_destroy`), `ipc/sem.c` (`newary`, `do_semtimedop`, `semctl_main`, `exit_sem`), `ipc/msg.c` (`newque`, `do_msgsnd`, `do_msgrcv`, `ksys_msgctl`, `prepare_copy`), `ipc/msgutil.c` (`load_msg`, `copy_msg`), `ipc/ipc_sysctl.c` and `include/linux/ipc_namespace.h` (limits), `include/linux/ipc.h` |
| Seccomp | `kernel/seccomp.c` (`seccomp_check_filter`, `seccomp_prepare_filter`, `seccomp_attach_filter`, `seccomp_run_filters`, `seccomp_uprobe_exception`, `__seccomp_filter`, `__secure_computing_strict`, `seccomp_set_mode_strict`, `seccomp_set_mode_filter`, `seccomp_can_sync_threads`, `seccomp_sync_threads`, `do_seccomp`, `prctl_set_seccomp`), `net/core/filter.c` (`bpf_check_classic`, `chk_code_allowed`, `check_load_and_stores`, `bpf_prepare_filter`, and `bpf_convert_filter`: the eBPF length and the division by zero), `kernel/signal.c` (`force_sig_seccomp`, `force_sig_info_to_task`), `include/asm-generic/seccomp.h` and `arch/x86/include/asm/seccomp.h` (strict mode's calls, native and i386), `arch/{x86,arm64,riscv}/include/asm/syscall.h` (`syscall_get_arch`, `syscall_get_arguments`, `syscall_rollback`), `arch/riscv/kernel/traps.c` (`do_trap_ecall_u`: `epc` past the `ecall` before the check), `arch/x86/kernel/process.c` (`disable_TSC`, `get_tsc_mode`, `set_tsc_mode`, `arch_setup_new_exec`), `kernel/sys.c` (`PR_SET_NO_NEW_PRIVS`, `PR_GET_SECCOMP`, `PR_SET_TSC`), `fs/proc/array.c` (`task_seccomp`) |
| File-system notification (inotify) | `fs/notify/inotify/inotify_user.c` (the calls, `inotify_read`, `inotify_ioctl`, `inotify_update_existing_watch`, `inotify_new_watch`, `inotify_arg_to_mask`), `fs/notify/inotify/inotify_fsnotify.c` (`inotify_handle_inode_event`, `inotify_merge`, `inotify_freeing_mark`), `fs/notify/inotify/inotify.h`, `fs/notify/fsnotify.c` (`__fsnotify_parent`, `fsnotify`, `send_to_group`, `fsnotify_handle_event`), `fs/notify/notification.c` (`fsnotify_insert_event`, the overflow event), `fs/notify/mark.c` (the group's mark list), `fs/notify/fdinfo.c` (`inotify_fdinfo`), `include/linux/fsnotify.h` (the VFS hooks and what each reports), `include/linux/fsnotify_backend.h` (the event bits), and where the VFS calls the hooks: `fs/open.c` (`vfs_open`, `vfs_fallocate`, `do_truncate`, `chmod_common`, `chown_common`), `fs/file_table.c` (`__fput`), `fs/read_write.c` (`vfs_read`, `vfs_readv`, `vfs_write`, `vfs_writev`, `do_sendfile`, `vfs_copy_file_range`), `fs/attr.c` (`notify_change`), `fs/readdir.c` (`iterate_dir`), `fs/splice.c`, `fs/namei.c`, `fs/utimes.c`, `fs/xattr.c`, and `fs/exec.c` |
| System-call entry | `arch/x86/entry/syscall_64.c` (`do_syscall_64`, `do_syscall_x64`: the number as an `int`), `arch/arm64/kernel/syscall.c` (`el0_svc_common`, `invoke_syscall`: likewise), `arch/riscv/kernel/traps.c` (`do_trap_ecall_u`: the whole `long`) |
| Machine administration | `mm/swapfile.c` (`swapon`, `swapoff`), `include/linux/swap.h` (`SWAP_FLAGS_VALID`), `kernel/reboot.c` (`reboot`), `include/uapi/linux/reboot.h`, `kernel/acct.c` (`acct`), `kernel/sys.c` (`sethostname`, `setdomainname`), `fs/open.c` (`vhangup`, `chroot`), `arch/x86/kernel/ioport.c` (`ioperm`, `iopl`), `kernel/module/main.c` (`init_module`, `finit_module`, `delete_module`, `copy_module_from_user`), `include/uapi/linux/module.h`, `include/linux/moduleparam.h` (`MODULE_NAME_LEN`), `kernel/printk/printk.c` (`do_syslog`, `check_syslog_permissions`, `syslog_action_restricted`), `include/linux/syslog.h`, `init/Kconfig` (`LOG_BUF_SHIFT`), `include/linux/security.h` and `security/commoncap.c` (without security modules: `cap_settime`, `security_syslog`) |
| Setting the clocks | `kernel/time/time.c` (`settimeofday`, `do_sys_settimeofday64`, `adjtimex`), `kernel/time/posix-timers.c` (`clock_settime`, `clock_adjtime`, `clockid_to_kclock`), `kernel/time/posix-cpu-timers.c` (`posix_cpu_clock_set`, `pid_for_clock`), `kernel/time/posix-clock.c` (`get_clock_desc`, `pc_clock_settime`, `pc_clock_adjtime`), `kernel/time/timekeeping.c` (`timekeeping_validate_timex`, `__do_adjtimex`), `kernel/time/ntp.c` (the initial NTP state, `ntp_adjtimex`, `pps_fill_timex`), `include/linux/timex.h`, `include/uapi/linux/timex.h`, `include/linux/time64.h` (`timespec64_valid_settod`), `include/linux/jiffies.h`, `include/asm-generic/param.h`, and `include/uapi/asm-generic/param.h` (`USER_TICK_USEC`) |
| Mounts | `fs/namespace.c` (`mount`, `umount`, `pivot_root`, `open_tree`, `open_tree_attr`, `mount_setattr`, `move_mount`, `fsmount`, `may_mount`, `copy_mount_options`, `path_mount`, `build_mount_kattr`, `build_mount_idmapped`), `fs/fsopen.c` (`fsopen`, `fspick`, `fsconfig`), `include/uapi/linux/mount.h`, `include/linux/file.h` (`FD_ADD`, `FD_PREPARE`: the descriptor before the file), `mm/util.c` (`strndup_user`) |
| POSIX message queues | `ipc/mqueue.c` (`do_mq_open`, `prepare_open`, `mqueue_create_attr`, `mqueue_get_inode`: the limits and the `RLIMIT_MSGQUEUE` charge, `mq_unlink`, `do_mq_timedsend`, `do_mq_timedreceive`, `wq_add`, `wq_sleep`, `pipelined_send`, `pipelined_receive`, `msg_insert`, `msg_get`, `__do_notify`, `do_mq_notify`, `do_mq_getsetattr`, `mqueue_read_file`, `mqueue_flush_file`, `mqueue_poll_file`), `ipc/mq_sysctl.c` and `include/linux/ipc_namespace.h` (the limits), `include/linux/msg.h` and `include/linux/rbtree_types.h` (the charged structure sizes), `include/uapi/linux/mqueue.h`, `fs/namei.c` (`lookup_noperm_common`, `vfs_mkobj`, `__check_sticky`), `fs/libfs.c` (`simple_lookup`), `net/netlink/af_netlink.c` (`netlink_getsockbyfd`) |
| Scheduling attributes | `kernel/sched/syscalls.c` (`sched_setscheduler`, `sched_setparam`, `sched_setattr`, `sched_getattr`, `sched_copy_attr`, `__sched_setscheduler`, `user_check_sched_setscheduler`, `__setscheduler_params`, `get_params`, `set_user_nice`, `is_nice_reduction`, `__normal_prio`, `sched_get_priority_max`/`min`, `sched_rr_get_interval`), `kernel/sched/core.c` (`sched_fork`, `to_ratio`), `kernel/sched/fair.c` (`__setparam_fair`, `sysctl_sched_base_slice`, `get_rr_interval_fair`), `kernel/sched/rt.c` (`get_rr_interval_rt`, the real-time bandwidth), `kernel/sched/deadline.c` (`__checkparam_dl`, `sched_dl_overflow`, `__dl_overflow`, the fair server's bandwidth), `kernel/sched/sched.h` (the policy classes), `include/linux/sched/{prio,rt,deadline}.h`, `include/uapi/linux/sched.h`, `include/uapi/linux/sched/types.h` (`struct sched_attr`), `kernel/sys.c` (`setpriority`, `getpriority`, `PR_SET_TIMERSLACK`), `kernel/fork.c` (`default_timer_slack_ns`), `block/ioprio.c` (`ioprio_set`, `ioprio_get`, `ioprio_check_cap`), `block/blk-ioc.c` (`set_task_ioprio`, `copy_io`), `include/linux/ioprio.h` (`__get_task_ioprio`), `include/uapi/linux/ioprio.h` |
| Supplementary groups, read-ahead, and range sync | `kernel/groups.c` (`setgroups`, `getgroups`), `mm/readahead.c` (`ksys_readahead`), `fs/sync.c` (`sync_file_range`) |
| Process memory access and kernel-object comparison | `mm/process_vm_access.c` (`process_vm_rw`, `process_vm_rw_core`, `process_vm_rw_single_vec`, `process_vm_rw_pages`), `mm/gup.c` (`check_vma_flags`, `__get_user_pages`, `gup_vma_lookup`, `faultin_page_range`: `VM_READ` for reads, the pinned prefix), `lib/iov_iter.c` (`__import_iovec`, `import_ubuf`, `iovec_from_user`, `copy_iovec_from_user`, `iov_iter_iovec_advance`: `access_ok` on the whole length before `MAX_RW_COUNT`, a single segment capped first), `kernel/ptrace.c` (`__ptrace_may_access`), `kernel/fork.c` (`mm_access`, `may_access_mm`), `mm/madvise.c` (`process_madvise`, `vector_madvise`, `madvise_should_skip`, `process_madvise_remote_valid`), `kernel/pid.c` (`pidfd_get_task`), `kernel/kcmp.c` (`kcmp`, `kcmp_ptr`, `kcmp_epoll_target`), `fs/eventpoll.c` (`get_epoll_tfile_raw_ptr`, `ep_find_tfd`), `include/linux/ptrace.h` (`PTRACE_MODE_*`), `include/uapi/linux/kcmp.h`, `ipc/sem.c` (`copy_semundo`, `get_undo_list`, `find_alloc_undo`, `exit_sem`), `block/blk-ioc.c` (`copy_io`, `exit_io_context`) |
| Memory locking and sealing | `mm/mlock.c` (`can_do_mlock`, `mlock_fixup`, `apply_vma_lock_flags`, `count_mm_mlocked_page_nr`, `__mlock_posix_error_return`, `do_mlock`, `mlock2`, `munlock`, `apply_mlockall_flags`, `mlockall`, `munlockall`), `mm/mseal.c` (`range_contains_unmapped`, `mseal_apply`, `do_mseal`), `mm/gup.c` (`populate_vma_page_range`, `__mm_populate`), `mm/mmap.c` (`check_brk_limits`, `brk`, `mlock_future_ok`, `do_mmap`, `dup_mmap`), `mm/vma.c` (`vms_gather_munmap_vmas`, `vms_complete_munmap_vmas`, `mmap_region`, `do_brk_flags`: sealed and locked VMAs), `mm/mremap.c` (`check_prep_vma`, `resize_is_valid`, `vrm_stat_account`, `move_vma`, `dontunmap_complete`), `mm/madvise.c` (`madvise_dontneed_free_valid_vma`, `can_madv_lru_vma`, `madvise_remove`, `can_madvise_modify`, `is_discard`), `mm/mprotect.c` (`mprotect_fixup`), `kernel/fork.c` (`mm_init`: `def_flags`), `include/linux/mm.h` (`VM_LOCKED`, `VM_LOCKONFAULT`, `VM_SEALED`, `VM_SPECIAL`, `vma_is_accessible`), `include/uapi/asm-generic/mman.h` (`MCL_*`), `include/uapi/asm-generic/mman-common.h` (`MLOCK_ONFAULT`, `MAP_LOCKED`, the `MADV_*` advice) |
| Restartable sequences | `kernel/rseq.c` (`rseq`: the registration checks and fields, `rseq_reset_ids`; `rseq_handle_cs`, `rseq_slowpath_update_usr`, `__rseq_signal_deliver`), `include/linux/rseq_entry.h` (`rseq_update_user_cs`: the section, abort-handler, and signature checks; `rseq_set_ids_get_csaddr`, `rseq_update_usr`, `rseq_exit_user_update`, `__rseq_exit_to_user_mode_restart`), `include/linux/rseq.h` (`rseq_signal_deliver`, `rseq_sched_switch_event`, `rseq_force_update`, `rseq_reset`, `rseq_execve`, `rseq_fork`), `include/linux/rseq_types.h` (`struct rseq_event`), `include/uapi/linux/rseq.h` (`struct rseq`, `struct rseq_cs`, `RSEQ_FLAG_UNREGISTER`, `RSEQ_CPU_ID_UNINITIALIZED`), `arch/{arm64,x86,riscv}/Kconfig` (all three select the generic IRQ entry, which ties section checks to user-mode interrupts) |

Code comments name the kernel function whose behavior an implementation
follows (for example `do_mprotect_pkey` or `madvise_walk_vmas`); that
function is in one of these files.
