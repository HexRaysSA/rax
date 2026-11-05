# CR0 cache controls across INIT

Software x86 INIT now preserves CR0.CD and CR0.NW, sets ET, and clears the
remaining CR0 bits. It previously published `0x60000010` for every INIT,
changing either cache-control bit that was clear. Constructor and reset CR0
now use `0x60000010`; both previously left CR0 at zero. The owning regression
covers all three cache configurations and checks reset after each INIT. This
change qualifies CR0 defaults, not every power-on register or reset-vector field.

| CR0.CD/NW before INIT | CR0 after INIT |
|---|---|
| `00` | `0x00000010` |
| `10` | `0x40000010` |
| `11` | `0x60000010` |

The source is Intel SDM revision086, Vol3A Table11-1, note2, in the retained
[combined manual](../../specifications/x86_64/325462-sdm-vol-1-2abcd-3abcd-4-1.pdf).
The note specifies: "The CD and NW flags are unchanged, bit 4 is set to 1,
all other bits are cleared."
The retained [Linux6.8 source](../kvm-native-private-state/references/linux-x86-v6.8.c)
also explicitly preserves these bits in `kvm_vcpu_reset(..., true)`.

`native-control.c` creates independent KVM graphs with 1, 2 and 4 CPUs, seeds
the three cache settings, delivers broadcast INIT, and requires the exact
recipient count. `GET_MP_STATE` accepts the pending reset; RAX is not linked.
Every CPU must show reset RIP/GPR state and the expected CR0. An explicitly
prepared native entry then executes `MOV EAX,CR0` and writes its value to an
output port. All21 observations matched. This is not a SIPI startup control
or physical bare-metal INIT qualification.

`software-control.rs` repeats the same cache-setting matrix through the public
RAX CPU API. The unchanged library produced14 mismatches out of21 observations.
The baseline source, library hash, commands and outputs are recorded in
[qualification.json](qualification.json). Two earlier unicast fixture attempts
reported no recipient and stopped before any comparison. Their raw records are
retained separately; their cause is unknown. The broadcast control verifies
delivery and reset before comparing CR0.

The corrected public software control now passes all 21 INIT observations and
all constructor/reset checks, with zero mismatches. It executes the actual RAX
software CPU through Rosetta, separately from native KVM and HVF. Both INIT unit
tests also pass in the frozen unfiltered Apple Silicon library run: 12,440 passed,
36 ignored, none failed and no filter. The mask update uses O(1) time and space. This component does
not close the broader native checkpoint, scheduling or HVF requirements.

The first combined qualification compiled successfully but failed both startup
unit tests: the new reset assertion observed zero CR0, and the older INIT
assertion expected cache flags which the zero-CR0 constructor had never set.
Those failures are retained. Constructor and reset now establish the specified
CR0 flags; the corrected public probe compares both initial and reset CR0 as
well as all21 INIT observations. The subsequent corrected execution passes;
the initial failed attempts remain recorded as failures.
