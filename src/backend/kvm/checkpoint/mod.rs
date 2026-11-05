//! Native banks composed under the real managed VM boundary.
mod bank;
mod bounded;
mod clock;
mod cpu;
mod deferred;
mod msrs;
mod nested;
mod owner;
mod profile;
mod shared;
mod sregs2;

pub(super) use clock::Image as ClockImage;
pub(super) use deferred::Image as DeferredImage;
pub(super) use owner::Image;
