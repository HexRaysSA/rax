// Bochs reference functions below retain their LGPL-2.0-or-later notice.
// Computational register shim only: this does not execute guest instructions.
#include <cstdint>
#include <iostream>
using Bit32u = uint32_t;
using bx_address = uint64_t;
#define BX_CPU_THIS_PTR this->
#define BX_DEBUG_TRAP_HIT (1 << 12)
#define BX_HWDebugIO 2
#define BX_ERROR(x) ((void)0)
struct Control {
 uint64_t value=0;
 Bit32u get32() const { return (Bit32u)value; }
 unsigned get_bp_enabled() const { return value & 255; }
 unsigned get_DE() const { return (value >> 3) & 1; }
 unsigned get_LEN0() const { return (value >> 18) & 3; }
 unsigned get_LEN1() const { return (value >> 22) & 3; }
 unsigned get_LEN2() const { return (value >> 26) & 3; }
 unsigned get_LEN3() const { return (value >> 30) & 3; }
 unsigned get_R_W0() const { return (value >> 16) & 3; }
 unsigned get_R_W1() const { return (value >> 20) & 3; }
 unsigned get_R_W2() const { return (value >> 24) & 3; }
 unsigned get_R_W3() const { return (value >> 28) & 3; }
};
class BX_CPU_C {
public:
 Control dr7,cr4;
 uint64_t dr[4]={0,0,0,0};
 Bit32u debug_trap=0;
 unsigned async_event=0;
 Bit32u hwdebug_compare(bx_address,unsigned,unsigned,unsigned);
 void iobreakpoint_match(unsigned,unsigned);
};
/////////////////////////////////////////////////////////////////////////
// $Id$
/////////////////////////////////////////////////////////////////////////
//
//   Copyright (c) 2010-2026 Stanislav Shwartsman
//          Written by Stanislav Shwartsman [sshwarts at sourceforge net]
//
//  This library is free software; you can redistribute it and/or
//  modify it under the terms of the GNU Lesser General Public
//  License as published by the Free Software Foundation; either
//  version 2 of the License, or (at your option) any later version.
//
//  This library is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
//  Lesser General Public License for more details.
//
//  You should have received a copy of the GNU Lesser General Public
//  License along with this library; if not, write to the Free Software
//  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA B 02110-1301 USA
//
/////////////////////////////////////////////////////////////////////////

Bit32u BX_CPU_C::hwdebug_compare(bx_address laddr_0, unsigned size, unsigned opa, unsigned opb)
{
  Bit32u dr7 = BX_CPU_THIS_PTR dr7.get32();

  static bx_address alignment_mask[4] =
    // 00b=1  01b=2  10b=undef(8)  11b=4
    {  0x0,   0x1,   0x7,          0x3   };

  bx_address laddr_n = laddr_0 + (size - 1);
  Bit32u dr_op[4], dr_len[4];

  // If *any* enabled breakpoints matched, then we need to
  // set status bits for *all* breakpoints, even disabled ones,
  // as long as they meet the other breakpoint criteria.
  // dr6_mask is the return value.  These bits represent the bits
  // to be OR'd into DR6 as a result of the debug event.
  Bit32u dr6_mask = 0;

  dr_len[0] = BX_CPU_THIS_PTR dr7.get_LEN0();
  dr_len[1] = BX_CPU_THIS_PTR dr7.get_LEN1();
  dr_len[2] = BX_CPU_THIS_PTR dr7.get_LEN2();
  dr_len[3] = BX_CPU_THIS_PTR dr7.get_LEN3();

  dr_op[0] = BX_CPU_THIS_PTR dr7.get_R_W0();
  dr_op[1] = BX_CPU_THIS_PTR dr7.get_R_W1();
  dr_op[2] = BX_CPU_THIS_PTR dr7.get_R_W2();
  dr_op[3] = BX_CPU_THIS_PTR dr7.get_R_W3();

  for (unsigned n=0;n<4;n++) {
    bx_address dr_start = BX_CPU_THIS_PTR dr[n] & ~alignment_mask[dr_len[n]];
    bx_address dr_end = dr_start + alignment_mask[dr_len[n]];

    // See if this instruction address matches any breakpoints
    if ((dr_op[n]==opa || dr_op[n]==opb) &&
         (laddr_0 <= dr_end) &&
         (laddr_n >= dr_start)) {
      dr6_mask |= (1<<n);
      // tell if breakpoint was enabled
      if (dr7 & (3 << n*2)) {
        dr6_mask |= BX_DEBUG_TRAP_HIT;
      }
    }
  }

  return dr6_mask;
}
void BX_CPU_C::iobreakpoint_match(unsigned port, unsigned len)
{
  // Only compare debug registers if any breakpoints are enabled
  if (BX_CPU_THIS_PTR cr4.get_DE() && BX_CPU_THIS_PTR dr7.get_bp_enabled())
  {
    Bit32u dr6_bits = hwdebug_compare(port, len, BX_HWDebugIO, BX_HWDebugIO);
    if (dr6_bits) {
      BX_CPU_THIS_PTR debug_trap |= dr6_bits;
      if (BX_CPU_THIS_PTR debug_trap & BX_DEBUG_TRAP_HIT) {
        BX_ERROR(("#DB: I/O breakpoint hit - report debug trap on next instruction"));
        BX_CPU_THIS_PTR async_event = 1;
      }
    }
  }
}
int main() {
 uint64_t index,control,extensions,port,size;
 while(std::cin >> index >> control >> extensions) {
  BX_CPU_C cpu;cpu.dr7.value=control;cpu.cr4.value=extensions;
  for(auto &address:cpu.dr) { if(!(std::cin >> address)) return 2; }
  if(!(std::cin >> port >> size)) return 3;
  cpu.iobreakpoint_match((unsigned)port,(unsigned)size);
  std::cout << index << " " << (cpu.async_event ? cpu.debug_trap : 0) << "\n";
 }
}
