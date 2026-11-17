//! Private memory-owner protocol for host workers of one guest process family.
//!
//! The broker owns structural memory state. Workers transfer requests and
//! backing descriptors over dedicated channels and execute only during a
//! validated turn. These components do not themselves select guest clone
//! policy or enable the broker in the process scheduler.

mod broker;
mod channel;
mod client;
mod cpu;
mod memory;
mod operations;
mod physical;
mod turns;
mod view;
mod wire;

pub(crate) use broker::{BackingId, Broker, Event, ForkMetadata};
pub(crate) use channel::{Channel, Frame};
pub(crate) use client::{Access, Client, RemoteError, Session};
pub(crate) use cpu::OwnerMemory;
pub(crate) use memory::{Grant, MemoryOwner, OwnerError, Registration, SpaceId};
pub(crate) use turns::{Turn, Turns, WorkerId};
pub(crate) use view::View;
pub(crate) use wire::{
    Failure as MemoryFailure, Map, Operation, PreparationFailure, PreparationKind, ReadKind, Value,
};
