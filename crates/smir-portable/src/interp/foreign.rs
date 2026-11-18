//! Foreign code: machine code of another processor in the same process,
//! which portable code calls through bridges (chapter 07 of the
//! specification).
//!
//! The engine has no processor of its own for such code. The embedder
//! supplies one, a [`Foreign`], which has the images the program's bridges
//! name, memory of its own that the code runs in, and a way to enter code
//! there and run it until it returns. What crosses is the engine's affair
//! and is the same for every processor: a frame of 80 bytes that says where
//! the arguments are and where the result goes, which the bridge's stub in
//! the foreign code is entered with.
//!
//! A crossing is a transition: it has an identity and a generation, which
//! the frame carries and the stub must leave as they are. The stub says in
//! the frame that it returned; a frame that comes back saying anything
//! else, or changed in what was not the stub's to change, is no return, and
//! the program ends there.

use std::sync::atomic::Ordering;

use crate::Error;
use crate::ir::{Bridge, BridgeConvention, ForeignIsa, Type, Value};

use super::exec::{Step, internal};
use super::int;
use super::process::{Context, locked};

/// The size of a frame, which is aligned to 16 bytes.
pub const FRAME_BYTES: usize = 80;
/// The revision of the protocol the frame is of.
pub const FRAME_REVISION: u32 = 1;
/// What a frame says of its transition: that foreign code was entered and
/// has not returned.
pub const STATUS_ENTERED: u32 = 1;
/// That it is suspended in a call back into portable code.
pub const STATUS_SUSPENDED: u32 = 2;
/// That the foreign function returned and its result is in place.
pub const STATUS_RETURNED: u32 = 3;
/// That an exception left the foreign function.
pub const STATUS_RAISED: u32 = 4;
/// That the transition ended with nothing to go on with.
pub const STATUS_TERMINATED: u32 = 5;
/// The size of the header of an argument in the arena.
pub const ENTRY_BYTES: usize = 32;

/// The processor could not do what was asked: memory it has not, code that
/// faulted or did not come back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ForeignFault;

/// The embedder's processor for a program's foreign code.
///
/// A process has one, which its host hands over when the process starts
/// ([`Host::foreign`](super::Host::foreign)). The engine asks it for one
/// thing at a time: foreign code of two threads of a program never runs at
/// the same moment.
pub trait Foreign: Send {
    /// The processor this is.
    fn isa(&self) -> ForeignIsa;

    /// Where the code is that is `size` bytes at `offset` of the image with
    /// this SHA-256: its address in the processor's memory, or nothing if
    /// the processor has no such image or those bytes of it are no code.
    fn code(&mut self, image: &[u8; 32], offset: u64, size: u64) -> Option<u64>;

    /// Memory for one call's frame, arguments and result: `bytes` zero
    /// bytes at an address that is a multiple of 16, which foreign code may
    /// read and write, until it is released.
    fn allocate(&mut self, bytes: u64) -> Result<u64, ForeignFault>;

    /// Give back what [`allocate`](Self::allocate) gave at this address.
    fn release(&mut self, address: u64);

    fn write(&mut self, address: u64, bytes: &[u8]) -> Result<(), ForeignFault>;

    fn read(&mut self, address: u64, buffer: &mut [u8]) -> Result<(), ForeignFault>;

    /// Call the code at `entry` with one argument, the address `frame`,
    /// passed as `convention` has it, on the stack of the program's thread
    /// `thread`, and run it until it returns.
    fn enter(
        &mut self,
        thread: u64,
        convention: BridgeConvention,
        entry: u64,
        frame: u64,
    ) -> Result<(), ForeignFault>;
}

/// The arguments as they lie in the arena: for each a header, then its
/// bytes at the next offset that has its alignment. A header is the
/// declaration of the argument's type, zero, the size and the alignment of
/// its bytes, and how far on the next header is, which for the last is the
/// end of the arena.
fn arena(bridge: &Bridge, arguments: &[u128]) -> Vec<u8> {
    let mut arena = Vec::new();
    for (argument, bits) in bridge.arguments.iter().zip(arguments) {
        let entry = arena.len();
        let payload = (entry + ENTRY_BYTES).next_multiple_of(argument.alignment as usize);
        let next = (payload + argument.bytes as usize).next_multiple_of(8);
        arena.resize(next, 0);
        arena[entry..entry + 4].copy_from_slice(&argument.declaration.to_le_bytes());
        for (at, word) in [
            (8, argument.bytes),
            (16, argument.alignment),
            (24, (next - entry) as u64),
        ] {
            arena[entry + at..entry + at + 8].copy_from_slice(&word.to_le_bytes());
        }
        arena[payload..payload + argument.bytes as usize]
            .copy_from_slice(&bits.to_le_bytes()[..argument.bytes as usize]);
    }
    arena
}

/// A frame for a call through `bridge`: entered, and nothing else yet.
fn frame(bridge: &Bridge, places: [u64; 4], transition: u64, generation: u64) -> [u8; FRAME_BYTES] {
    let [arguments, arguments_bytes, result, result_bytes] = places;
    let mut frame = [0; FRAME_BYTES];
    frame[0..4].copy_from_slice(&FRAME_REVISION.to_le_bytes());
    frame[64..68].copy_from_slice(&STATUS_ENTERED.to_le_bytes());
    for (at, word) in [
        (8, u64::from(bridge.id)),
        (16, arguments),
        (24, arguments_bytes),
        (32, result),
        (40, result_bytes),
        (48, transition),
        (72, generation),
    ] {
        frame[at..at + 8].copy_from_slice(&word.to_le_bytes());
    }
    frame
}

/// Call foreign code through the bridge at `index` with the bits of its
/// arguments, and return the bits of what it returned. A step other than
/// going on is how the program ends if the foreign code does not return as
/// a bridge returns.
pub(super) fn call(
    context: &Context,
    index: u32,
    arguments: &[u128],
) -> Result<Result<Vec<u128>, Step>, Error> {
    let process = context.process;
    let module = process.module;
    let (Some(bridge), Some(entry), Some(processor)) = (
        module.bridges().get(index as usize),
        process.entries.get(index as usize),
        &process.foreign,
    ) else {
        return Err(internal("bridge index"));
    };
    let arena = arena(bridge, arguments);
    // One block: the frame, the arena, and the result at the next multiple
    // of 16.
    let result_at = (FRAME_BYTES + arena.len()).next_multiple_of(16);
    let transition = process.transitions.fetch_add(1, Ordering::AcqRel) + 1;
    // Never a generation that an earlier transition had.
    let generation = transition.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;

    let mut processor = locked(processor);
    let Ok(block) = processor.allocate(result_at as u64 + bridge.result_bytes) else {
        return Ok(Err(Step::Trap("foreign_fault")));
    };
    let entered = frame(
        bridge,
        [
            block + FRAME_BYTES as u64,
            arena.len() as u64,
            if bridge.result_bytes == 0 {
                0
            } else {
                block + result_at as u64
            },
            bridge.result_bytes,
        ],
        transition,
        generation,
    );
    let mut returned = [0; FRAME_BYTES];
    let mut result = [0_u8; 16];
    let ran = processor
        .write(block, &entered)
        .and_then(|()| processor.write(block + FRAME_BYTES as u64, &arena))
        .and_then(|()| processor.enter(context.thread, bridge.convention, *entry, block))
        .and_then(|()| processor.read(block, &mut returned))
        .and_then(|()| {
            processor.read(
                block + result_at as u64,
                &mut result[..bridge.result_bytes as usize],
            )
        });
    processor.release(block);
    drop(processor);
    if ran.is_err() {
        return Ok(Err(Step::Trap("foreign_fault")));
    }
    // The stub's to change is the status, which says that it returned.
    // Everything else of the frame is the transition's, as it was entered.
    let mut expected = entered;
    expected[64..68].copy_from_slice(&STATUS_RETURNED.to_le_bytes());
    if returned != expected {
        return Ok(Err(Step::Trap("foreign_return")));
    }
    let bits = u128::from_le_bytes(result);
    let Some(ty) = module.bridge_signature(bridge).results.first() else {
        return Ok(Ok(Vec::new()));
    };
    let width = match module.ty(*ty) {
        Type::Int { bits } => *bits,
        Type::Float { format } => format.bits(),
        _ => return Err(internal("bridge result type")),
    };
    // A result of fewer bits than its bytes has nothing in the rest.
    if bits > int::mask(width) {
        return Ok(Err(Step::Trap("foreign_return")));
    }
    Ok(Ok(vec![bits]))
}

/// The bits a foreign function is given for a value: an unspecified value
/// goes as zero, and poison is nothing foreign code can be given.
pub(super) fn argument(value: Value) -> Result<Result<u128, Step>, Error> {
    Ok(match value {
        Value::Int(bits) => Ok(bits),
        Value::Undef => Ok(0),
        Value::Poison => Err(Step::LanguageUb("ub_foreign_argument")),
        _ => return Err(internal("foreign argument kind")),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{BridgeArgument, TypeId};

    fn bridge(arguments: &[(u32, u64, u64)]) -> Bridge {
        Bridge {
            id: 7,
            isa: ForeignIsa::X86_64,
            convention: BridgeConvention::SysV64,
            image: [0; 32],
            offset: 0,
            size: 1,
            signature: TypeId(0),
            arguments: arguments
                .iter()
                .map(|(declaration, bytes, alignment)| BridgeArgument {
                    declaration: *declaration,
                    bytes: *bytes,
                    alignment: *alignment,
                })
                .collect(),
            result_bytes: 8,
        }
    }

    #[test]
    fn arguments_lie_in_the_arena_each_after_its_header() {
        // A byte, a double word aligned to 16, and a half word.
        let bridge = bridge(&[(3, 1, 1), (9, 8, 16), (4, 2, 2)]);
        let arena = arena(&bridge, &[0xab, 0x1122_3344_5566_7788, 0xbeef]);
        let word = |at: usize| u64::from_le_bytes(arena[at..at + 8].try_into().unwrap());
        // The first: its header, its byte at 32, and the next header at the
        // next multiple of 8.
        assert_eq!((word(0), word(8), word(16), word(24)), (3, 1, 1, 40));
        assert_eq!(arena[32], 0xab);
        // The second: its bytes at the next multiple of 16 after its
        // header, which is 80.
        assert_eq!((word(40), word(48), word(56), word(64)), (9, 8, 16, 48));
        assert_eq!(word(80), 0x1122_3344_5566_7788);
        // The third, whose `next` is the end of the arena.
        assert_eq!((word(88), word(96), word(104), word(112)), (4, 2, 2, 40));
        assert_eq!(arena[120..122], [0xef, 0xbe]);
        assert_eq!(arena.len(), 128);
        // Everything else is zero, and no arguments are no arena.
        let used = [
            0..1,
            8..9,
            16..17,
            24..25,
            32..33,
            40..41,
            48..49,
            56..57,
            64..65,
        ];
        assert!(
            (0..80).all(|at| used.iter().any(|range| range.contains(&at)) || arena[at] == 0),
            "{arena:?}"
        );
        assert!(super::arena(&self::bridge(&[]), &[]).is_empty());
    }

    #[test]
    fn a_frame_says_where_everything_is_and_that_it_was_entered() {
        let frame = frame(&bridge(&[]), [0x1000, 40, 0x2000, 8], 5, 99);
        let half = |at: usize| u32::from_le_bytes(frame[at..at + 4].try_into().unwrap());
        let word = |at: usize| u64::from_le_bytes(frame[at..at + 8].try_into().unwrap());
        assert_eq!((half(0), half(4), word(8)), (FRAME_REVISION, 0, 7));
        assert_eq!(
            (word(16), word(24), word(32), word(40)),
            (0x1000, 40, 0x2000, 8)
        );
        assert_eq!(
            (word(48), word(56), half(64), half(68)),
            (5, 0, STATUS_ENTERED, 0)
        );
        assert_eq!(word(72), 99);
    }

    #[test]
    fn foreign_code_is_given_bits_and_never_poison() {
        assert!(matches!(argument(Value::Int(5)), Ok(Ok(5))));
        assert!(matches!(argument(Value::Undef), Ok(Ok(0))));
        assert!(matches!(
            argument(Value::Poison),
            Ok(Err(Step::LanguageUb("ub_foreign_argument")))
        ));
    }
}
