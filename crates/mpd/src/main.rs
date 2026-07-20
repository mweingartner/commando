//! `mpd` — Model-Paired Development CLI.
//!
//! A self-contained Rust binary that natively speaks the OpenSpec format
//! (via `openspec-core`) and layers the adversarial-gate pipeline on top:
//! phase state machine, durable gate ledger, deterministic checks, and a
//! harness-agnostic `next` brief. No Node runtime dependency.

#![deny(unsafe_code)]

mod allowlist;
pub mod candidate;
mod checks;
mod cli;
mod closure;
mod config;
mod digest;
mod directives;
mod git;
mod githooks;
mod harness;
mod ledger;
mod local_validation;
mod pathmatch;
mod personas;
mod phase;
mod sandbox;
#[cfg(target_os = "macos")]
mod sandbox_macos;
mod scaffold;

use std::process::ExitCode;

fn main() -> ExitCode {
    ExitCode::from(cli::run() as u8)
}
