//! `openspec-core` — a native, dependency-light engine for the OpenSpec
//! on-disk format.
//!
//! This crate reads, writes, validates, and merges OpenSpec specs and change
//! deltas without depending on the Node OpenSpec CLI at runtime. It treats the
//! OpenSpec *format* (documented in the `openspec-conventions` spec) as the
//! integration contract, so directories written here remain readable by the
//! reference implementation and vice versa.
//!
//! # Modules
//! - [`model`] — the domain types ([`Spec`], [`Requirement`], [`Scenario`],
//!   [`DeltaSpec`]).
//! - [`parse`] — fence-aware markdown → model.
//! - [`render`] — model → canonical markdown (idempotent form).
//! - [`validate`] — structural + convention checks.
//! - [`merge`] — apply a delta to a spec (the archive algorithm).
//! - [`schema`] — schema and change-metadata YAML.
//! - [`project`] — filesystem layout, discovery, status, archiving.
//! - [`date`] — dependency-free `YYYY-MM-DD` formatting.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod date;
pub mod error;
pub mod merge;
pub mod model;
pub mod names;
pub mod parse;
pub mod project;
pub mod render;
pub mod schema;
pub mod validate;

pub use error::{CoreError, Result};
pub use merge::{merge, MergeError, MergeStats};
pub use model::{DeltaSpec, Issue, Removed, Rename, Requirement, Scenario, Severity, Spec};
pub use names::{validate_capability_name, validate_change_name};
pub use parse::{parse_delta, parse_spec, ParseError};
pub use project::{ArchivePlan, Project, SpecUpdate, TaskStatus};
pub use render::{render_delta, render_spec};
pub use schema::{Artifact, ChangeMeta, Schema, YamlError};
pub use validate::{has_blocking, validate_delta, validate_spec};
