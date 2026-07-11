//! `mpd` — Model-Paired Development CLI.
//!
//! A self-contained Rust binary that natively speaks the OpenSpec format
//! (via `openspec-core`) and layers the adversarial-gate pipeline on top:
//! phase state machine, durable gate ledger, deterministic checks, and a
//! harness-agnostic `next` brief. No Node runtime dependency.

#![forbid(unsafe_code)]

mod checks;
mod cli;
mod config;
mod githooks;
mod harness;
mod ledger;
mod personas;
mod phase;
mod scaffold;

use std::process::ExitCode;

fn main() -> ExitCode {
    ExitCode::from(cli::run() as u8)
}
