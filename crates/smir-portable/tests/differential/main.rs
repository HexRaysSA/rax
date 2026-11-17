//! Actual production CLI versus independent frozen oracles. Never executes a guest.
mod canonical;
mod corpus;
mod cli;
mod mutations;
mod profile;
mod static_verify;
mod legacy_cut;
#[path = "mod.rs"]
mod support;
