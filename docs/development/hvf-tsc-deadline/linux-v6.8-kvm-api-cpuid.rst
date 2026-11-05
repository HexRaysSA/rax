.. SPDX-License-Identifier: GPL-2.0

4.46 KVM_GET_SUPPORTED_CPUID
----------------------------

:Capability: KVM_CAP_EXT_CPUID
:Architectures: x86
:Type: system ioctl
:Parameters: struct kvm_cpuid2 (in/out)
:Returns: 0 on success, -1 on error

::

  struct kvm_cpuid2 {
	__u32 nent;
	__u32 padding;
	struct kvm_cpuid_entry2 entries[0];
  };

  #define KVM_CPUID_FLAG_SIGNIFCANT_INDEX		BIT(0)
  #define KVM_CPUID_FLAG_STATEFUL_FUNC		BIT(1) /* deprecated */
  #define KVM_CPUID_FLAG_STATE_READ_NEXT		BIT(2) /* deprecated */

  struct kvm_cpuid_entry2 {
	__u32 function;
	__u32 index;
	__u32 flags;
	__u32 eax;
	__u32 ebx;
	__u32 ecx;
	__u32 edx;
	__u32 padding[3];
  };

This ioctl returns x86 cpuid features which are supported by both the
hardware and kvm in its default configuration.  Userspace can use the
information returned by this ioctl to construct cpuid information (for
KVM_SET_CPUID2) that is consistent with hardware, kernel, and
userspace capabilities, and with user requirements (for example, the
user may wish to constrain cpuid to emulate older hardware, or for
feature consistency across a cluster).

Dynamically-enabled feature bits need to be requested with
``arch_prctl()`` before calling this ioctl. Feature bits that have not
been requested are excluded from the result.

Note that certain capabilities, such as KVM_CAP_X86_DISABLE_EXITS, may
expose cpuid features (e.g. MONITOR) which are not supported by kvm in
its default configuration. If userspace enables such capabilities, it
is responsible for modifying the results of this ioctl appropriately.

Userspace invokes KVM_GET_SUPPORTED_CPUID by passing a kvm_cpuid2 structure
with the 'nent' field indicating the number of entries in the variable-size
array 'entries'.  If the number of entries is too low to describe the cpu
capabilities, an error (E2BIG) is returned.  If the number is too high,
the 'nent' field is adjusted and an error (ENOMEM) is returned.  If the
number is just right, the 'nent' field is adjusted to the number of valid
entries in the 'entries' array, which is then filled.

The entries returned are the host cpuid as returned by the cpuid instruction,
with unknown or unsupported features masked out.  Some features (for example,
x2apic), may not be present in the host cpu, but are exposed by kvm if it can
emulate them efficiently. The fields in each entry are defined as follows:

  function:
         the eax value used to obtain the entry

  index:
         the ecx value used to obtain the entry (for entries that are
         affected by ecx)

  flags:
     an OR of zero or more of the following:

        KVM_CPUID_FLAG_SIGNIFCANT_INDEX:
           if the index field is valid

   eax, ebx, ecx, edx:
         the values returned by the cpuid instruction for
         this function/index combination

The TSC deadline timer feature (CPUID leaf 1, ecx[24]) is always returned
as false, since the feature depends on KVM_CREATE_IRQCHIP for local APIC
support.  Instead it is reported via::

  ioctl(KVM_CHECK_EXTENSION, KVM_CAP_TSC_DEADLINE_TIMER)

if that returns true and you use KVM_CREATE_IRQCHIP, or if you emulate the
feature in userspace, then you can enable the feature for KVM_SET_CPUID2.


