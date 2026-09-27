# Armv7-M Architecture Reference Manual provenance

- Canonical title: *Armv7-M Architecture Reference Manual*
- Issuing organization: Arm Limited
- Document number and issue: ARM DDI 0403E.e (ID021621), Non-Confidential
- Date of issue: 15 February 2021
- Canonical location: https://developer.arm.com/documentation/ddi0403/ee/
- Copy retrieved from: https://www.pjrc.com/teensy/DDI0403Ee_arm_v7m_ref_manual.pdf
  (a mirror; its title page and PDF metadata identify the Arm issue above,
  created 16 February 2021; not compared against the copy on the Arm site)
- Retrieved: 26 September 2026
- SHA-256: `76500176d20f897eaf05eeadb5a6202cef641e332073b107905c8898e0ee0747`
- License: the Arm proprietary notice in the document applies; it is kept as
  distributed.

Used for the Cortex-M instruction layer (`src/isa/arm/cortex_m/exec/`) and
exception model (`src/isa/arm/cortex_m/exception.rs`): the Thumb encoding
tables of chapter A5 (A5.2 16-bit, A5.3 32-bit), the instruction pseudocode
of chapter A7, the special-register moves of B5.2 (MRS, MSR, CPS), and the
exception entry, return, priority, and escalation pseudocode of B1.5
(PushStack, ExceptionTaken, ReturnAddress, ExceptionReturn, PopStack,
ExecutionPriority, "Priority escalation"), plus HFSR.DEBUGEVT for BKPT
escalation (B3.2.16 and C1.5).
