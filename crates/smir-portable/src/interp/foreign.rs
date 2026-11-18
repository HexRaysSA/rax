//! Foreign code: machine code of another processor in the same process,
//! which portable code calls through bridges and which calls portable code
//! back (chapter 07 of the specification).
//!
//! The engine has no processor of its own for such code. The embedder
//! supplies one, a [`Foreign`], which has the images the program's bridges
//! name, memory of its own that the code runs in, and a way to enter code
//! there and run it until it comes back. What crosses is the engine's
//! affair and is the same for every processor: a frame of 80 bytes that
//! says where the arguments are and where the result goes.
//!
//! Portable code calls a foreign function by having the processor enter
//! the bridge's stub with a frame the engine made. Foreign code calls a
//! portable function by going, with a frame of its own making, to the entry
//! of a callback, a place in its image that the processor has taken over:
//! the code stops there, the engine runs the function, and the code goes on
//! with the result. The portable function may call foreign code again, and
//! so on, portable and foreign code by turns on one thread.
//!
//! A crossing is a transition: it has an identity and a generation, which
//! its frame carries. A stub says in its frame that it returned and must
//! leave the rest as it was; a frame that comes back saying anything else,
//! or changed in what was not the stub's to change, is no return, and the
//! program ends there.

use std::sync::atomic::Ordering;
use std::sync::{Mutex, MutexGuard};

use crate::Error;
use crate::ir::{
    Bridge, BridgeArgument, BridgeConvention, Callback, ForeignIsa, Type, TypeId, Value,
};

use super::exec::{Step, internal};
use super::int;
use super::process::{Context, locked, nested};

/// The size of a frame, which is aligned to 16 bytes.
pub const FRAME_BYTES: usize = 80;
/// The revision of the protocol the frame is of.
pub const FRAME_REVISION: u32 = 1;
/// What a frame says of its transition: that the code on the other side
/// was entered and has not returned.
pub const STATUS_ENTERED: u32 = 1;
/// That it is suspended in a call back into portable code.
pub const STATUS_SUSPENDED: u32 = 2;
/// That the function returned and its result is in place.
pub const STATUS_RETURNED: u32 = 3;
/// That an exception left the function.
pub const STATUS_RAISED: u32 = 4;
/// That the transition ended with nothing to go on with.
pub const STATUS_TERMINATED: u32 = 5;
/// The size of the header of an argument in the arena.
pub const ENTRY_BYTES: usize = 32;
/// How many calls of foreign code a thread may be in at once, one inside
/// another through callbacks.
pub const MAX_NESTED: usize = 32;

/// The processor could not do what was asked: memory it has not, code that
/// faulted or did not come back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ForeignFault;

/// How foreign code that was entered, or gone on with, came back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Crossing {
    /// It returned from the call it was entered for.
    Returned,
    /// It went to the entry of a callback, the address `entry` that
    /// [`Foreign::intercept`] gave, with the address `frame` as its one
    /// argument, and waits there to be gone on with.
    Called { entry: u64, frame: u64 },
}

/// The embedder's processor for a program's foreign code.
///
/// A process has one, which its host hands over when the process starts
/// ([`Host::foreign`](super::Host::foreign)). The engine asks it for one
/// thing at a time: foreign code of two threads of a program never runs at
/// the same moment. It does not hold the processor while portable code that
/// was called back runs, so another thread's foreign code may run then.
pub trait Foreign: Send {
    /// The processor this is.
    fn isa(&self) -> ForeignIsa;

    /// Where the code is that is `size` bytes at `offset` of the image with
    /// this SHA-256: its address in the processor's memory, or nothing if
    /// the processor has no such image or those bytes of it are no code.
    fn code(&mut self, image: &[u8; 32], offset: u64, size: u64) -> Option<u64>;

    /// Take over the code that is `size` bytes at `offset` of an image, as
    /// the entry of a callback: from now on foreign code that gets there
    /// does not run what is there but comes back to the engine, as
    /// [`Crossing::Called`] says. The entry's address, or nothing if the
    /// processor has no such code or cannot take code over.
    fn intercept(&mut self, _image: &[u8; 32], _offset: u64, _size: u64) -> Option<u64> {
        None
    }

    /// Memory for one call's frame, arguments and result: `bytes` zero
    /// bytes at an address that is a multiple of 16, which foreign code may
    /// read and write, until it is released.
    fn allocate(&mut self, bytes: u64) -> Result<u64, ForeignFault>;

    /// Give back what [`allocate`](Self::allocate) gave at this address.
    fn release(&mut self, address: u64);

    /// Write to memory that foreign code may write: what was allocated
    /// here, and the frame, the arguments and the result place of a
    /// callback, which are where the foreign code has them.
    fn write(&mut self, address: u64, bytes: &[u8]) -> Result<(), ForeignFault>;

    /// Read memory that foreign code may read.
    fn read(&mut self, address: u64, buffer: &mut [u8]) -> Result<(), ForeignFault>;

    /// Call the code at `entry` with one argument, the address `frame`,
    /// passed as `convention` has it, on the stack of the program's thread
    /// `thread`, and run it until it returns or goes to the entry of a
    /// callback. A thread whose foreign code waits at such an entry may be
    /// entered again: the new call is on the same stack, below the one that
    /// waits.
    fn enter(
        &mut self,
        thread: u64,
        convention: BridgeConvention,
        entry: u64,
        frame: u64,
    ) -> Result<Crossing, ForeignFault>;

    /// Go on with the foreign code of `thread` that waits at the entry of a
    /// callback, as if the entry had returned to it, until it returns or
    /// goes to such an entry again. What it waits for last goes on first.
    fn resume(&mut self, _thread: u64) -> Result<Crossing, ForeignFault> {
        Err(ForeignFault)
    }
}

/// Where each argument lies in an arena: its header, its bytes at the next
/// offset that has its alignment, and the next header at the next multiple
/// of 8 after them, which for the last argument is the end of the arena.
fn places(arguments: &[BridgeArgument]) -> Vec<(usize, usize, usize)> {
    let mut next = 0;
    arguments
        .iter()
        .map(|argument| {
            let entry = next;
            let payload = (entry + ENTRY_BYTES).next_multiple_of(argument.alignment as usize);
            next = (payload + argument.bytes as usize).next_multiple_of(8);
            (entry, payload, next)
        })
        .collect()
}

/// The arguments as they lie in the arena. A header is the declaration of
/// the argument's type, zero, the size and the alignment of its bytes, and
/// how far on the next header is.
fn arena(arguments: &[BridgeArgument], bits: &[u128]) -> Vec<u8> {
    let places = places(arguments);
    let mut arena = vec![0; places.last().map_or(0, |(_, _, end)| *end)];
    for ((argument, bits), (entry, payload, next)) in arguments.iter().zip(bits).zip(places) {
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

/// The identity and the generation of the process's next transition:
/// neither is one that an earlier transition had, and neither is zero.
fn transition(context: &Context) -> (u64, u64) {
    let transition = context.process.transitions.fetch_add(1, Ordering::AcqRel) + 1;
    let generation = transition.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    (transition, generation)
}

/// How many bits the values of a type a bridge passes have.
fn width(context: &Context, ty: TypeId) -> Result<u32, Error> {
    match context.process.module.ty(ty) {
        Type::Int { bits } => Ok(*bits),
        Type::Float { format } => Ok(format.bits()),
        _ => Err(internal("the type of a value at a bridge")),
    }
}

/// Call foreign code through the bridge at `index` with the bits of its
/// arguments, and return the bits of what it returned. A step other than
/// going on is how the program ends if the foreign code does not return as
/// a bridge returns, or how the calling activation ends if portable code
/// that was called back ended more than itself.
pub(super) fn call(
    context: &Context,
    index: u32,
    arguments: &[u128],
) -> Result<Result<Vec<u128>, Step>, Error> {
    let process = context.process;
    let module = process.module;
    let (Some(bridge), Some(entry), Some(held)) = (
        module.bridges().get(index as usize),
        process.entries.get(index as usize),
        &process.foreign,
    ) else {
        return Err(internal("bridge index"));
    };
    // Every call of foreign code inside another is deeper on this thread's
    // own stack too.
    let depth = context.local.crossings.get();
    if depth >= MAX_NESTED {
        return Ok(Err(Step::Resource("crossings")));
    }
    let arena = arena(&bridge.arguments, arguments);
    // One block: the frame, the arena, and the result at the next multiple
    // of 16.
    let result_at = (FRAME_BYTES + arena.len()).next_multiple_of(16);
    let (transition, generation) = transition(context);

    let mut processor = locked(held);
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
    let started = processor
        .write(block, &entered)
        .and_then(|()| processor.write(block + FRAME_BYTES as u64, &arena))
        .and_then(|()| processor.enter(context.thread, bridge.convention, *entry, block));
    context.local.crossings.set(depth + 1);
    let crossed = crossed(context, held, processor, bridge, started);
    context.local.crossings.set(depth);
    // The processor is held again, whatever happened, and the block is
    // given back, whatever happened.
    let mut processor = locked(held);
    let mut returned = [0; FRAME_BYTES];
    let mut result = [0_u8; 16];
    let read = match &crossed {
        Ok(Ok(())) => processor
            .read(block, &mut returned)
            .and_then(|()| {
                processor.read(
                    block + result_at as u64,
                    &mut result[..bridge.result_bytes as usize],
                )
            })
            .is_ok(),
        _ => false,
    };
    processor.release(block);
    drop(processor);
    if let Err(step) = crossed? {
        return Ok(Err(step));
    }
    if !read {
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
    // A result of fewer bits than its bytes has nothing in the rest.
    if bits > int::mask(width(context, *ty)?) {
        return Ok(Err(Step::Trap("foreign_return")));
    }
    Ok(Ok(vec![bits]))
}

/// See a call of foreign code through to its return: `started` is how its
/// code first came back, and each time it comes back at the entry of a
/// callback, the function it calls is run and the code gone on with. The
/// processor is not held while portable code runs, and not on return from
/// here.
fn crossed<'held>(
    context: &Context,
    held: &'held Mutex<Box<dyn Foreign>>,
    mut processor: MutexGuard<'held, Box<dyn Foreign>>,
    bridge: &Bridge,
    started: Result<Crossing, ForeignFault>,
) -> Result<Result<(), Step>, Error> {
    let mut crossing = started;
    loop {
        let (entry, frame) = match crossing {
            Err(ForeignFault) => return Ok(Err(Step::Trap("foreign_fault"))),
            Ok(Crossing::Returned) => return Ok(Ok(())),
            Ok(Crossing::Called { entry, frame }) => (entry, frame),
        };
        let request = match Request::read(context, &mut **processor, bridge, entry, frame)? {
            Ok(request) => request,
            Err(step) => return Ok(Err(step)),
        };
        drop(processor);
        let values = match nested(context, request.callback.function, &request.arguments)? {
            Ok(values) => values,
            Err(step) => return Ok(Err(step)),
        };
        processor = locked(held);
        if let Err(step) = request.answer(&mut **processor, &values)? {
            return Ok(Err(step));
        }
        crossing = processor.resume(context.thread);
    }
}

/// A call of a portable function that foreign code makes: which, with
/// what, and the frame it is made with.
struct Request<'run> {
    callback: &'run Callback,
    arguments: Vec<Value>,
    /// Where the frame is, and where it says the result goes.
    frame: u64,
    result: u64,
}

fn word(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().expect("eight bytes"))
}

impl<'run> Request<'run> {
    /// What foreign code asks for that waits at `entry` with the frame at
    /// `at`, in a call through `bridge`. Whatever is not exactly a call of
    /// the callback that has this entry is the trap `foreign_callback`: the
    /// function is not run.
    fn read(
        context: &Context<'_, '_, '_, 'run>,
        processor: &mut dyn Foreign,
        bridge: &Bridge,
        entry: u64,
        at: u64,
    ) -> Result<Result<Self, Step>, Error> {
        let refused = Ok(Err(Step::Trap("foreign_callback")));
        let process = context.process;
        let module = process.module;
        let Some(callback) = process
            .callbacks
            .get(&entry)
            .and_then(|index| module.callbacks().get(*index))
            // The function that was called says whether it calls back.
            .filter(|_| bridge.calls_back)
        else {
            return refused;
        };
        // The frame: as a frame is entered, of this callback, and of no
        // transition yet.
        let mut frame = [0; FRAME_BYTES];
        if at % 16 != 0 || processor.read(at, &mut frame).is_err() {
            return refused;
        }
        let places = places(&callback.arguments);
        let bytes = places.last().map_or(0, |(_, _, end)| *end);
        let (arena_at, result) = (word(&frame, 16), word(&frame, 32));
        let mut expected = [0; FRAME_BYTES];
        expected[0..4].copy_from_slice(&FRAME_REVISION.to_le_bytes());
        expected[64..68].copy_from_slice(&STATUS_ENTERED.to_le_bytes());
        for (offset, value) in [
            (8, u64::from(callback.id)),
            (16, arena_at),
            (24, bytes as u64),
            (32, result),
            (40, callback.result_bytes),
        ] {
            expected[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        if frame != expected || (result == 0) != (callback.result_bytes == 0) {
            return refused;
        }
        // The arena: the arguments the callback takes and nothing else, as
        // the engine itself would have laid them out.
        let mut arena = vec![0; bytes];
        if processor.read(arena_at, &mut arena).is_err() {
            return refused;
        }
        let function = &module.func(callback.function).signature;
        let mut arguments = Vec::with_capacity(places.len());
        let mut bits = Vec::with_capacity(places.len());
        for ((argument, ty), (_, payload, _)) in
            callback.arguments.iter().zip(&function.params).zip(&places)
        {
            let mut value = [0; 16];
            let size = argument.bytes as usize;
            value[..size].copy_from_slice(&arena[*payload..*payload + size]);
            let value = u128::from_le_bytes(value);
            // An argument of fewer bits than its bytes has nothing in the
            // rest.
            if value > int::mask(width(context, *ty)?) {
                return refused;
            }
            bits.push(value);
            arguments.push(Value::Int(value));
        }
        if arena != self::arena(&callback.arguments, &bits) {
            return refused;
        }
        // The crossing is a transition of its own, and its frame says so.
        let (transition, generation) = transition(context);
        if processor.write(at + 48, &transition.to_le_bytes()).is_err()
            || processor.write(at + 72, &generation.to_le_bytes()).is_err()
        {
            return refused;
        }
        Ok(Ok(Self {
            callback,
            arguments,
            frame: at,
            result,
        }))
    }

    /// Put what the function returned where the frame said, and say in the
    /// frame that it returned.
    fn answer(
        &self,
        processor: &mut dyn Foreign,
        values: &[Value],
    ) -> Result<Result<(), Step>, Error> {
        let bytes = self.callback.result_bytes as usize;
        let bits = match (values, bytes) {
            ([], 0) => 0,
            ([value], 1..) => match argument(*value)? {
                Ok(bits) => bits,
                Err(step) => return Ok(Err(step)),
            },
            _ => return Err(internal("callback result arity")),
        };
        let written = processor
            .write(self.result, &bits.to_le_bytes()[..bytes])
            .and_then(|()| processor.write(self.frame + 64, &STATUS_RETURNED.to_le_bytes()));
        Ok(written.map_err(|ForeignFault| Step::Trap("foreign_callback")))
    }
}

/// The bits foreign code is given for a value, as an argument or as what a
/// function it called back returned: an unspecified value goes as zero, and
/// poison is nothing foreign code can be given.
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
            calls_back: false,
        }
    }

    #[test]
    fn arguments_lie_in_the_arena_each_after_its_header() {
        // A byte, a double word aligned to 16, and a half word.
        let passed = bridge(&[(3, 1, 1), (9, 8, 16), (4, 2, 2)]).arguments;
        let arena = arena(&passed, &[0xab, 0x1122_3344_5566_7788, 0xbeef]);
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
        assert_eq!(places(&passed), [(0, 32, 40), (40, 80, 88), (88, 120, 128)]);
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
        assert!(super::arena(&[], &[]).is_empty());
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
