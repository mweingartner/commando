//! The crate's unified error type.

use crate::merge::MergeError;
use crate::parse::ParseError;
use crate::schema::YamlError;
use std::fmt;

/// Any error surfaced by `openspec-core`'s filesystem-facing operations.
#[derive(Debug)]
pub enum CoreError {
    /// An underlying I/O failure (message preserved).
    Io(String),
    /// A markdown parse failure.
    Parse(ParseError),
    /// A delta merge failure.
    Merge(MergeError),
    /// A YAML decode failure.
    Yaml(YamlError),
    /// A required resource (spec, change, capability) was not found.
    NotFound(String),
    /// A create/move target already exists.
    AlreadyExists(String),
    /// No `openspec/` directory was found from the starting path.
    NoProject,
}

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CoreError::Io(m) => write!(f, "io error: {m}"),
            CoreError::Parse(e) => write!(f, "parse error: {e}"),
            CoreError::Merge(e) => write!(f, "merge error: {e}"),
            CoreError::Yaml(e) => write!(f, "yaml error: {e}"),
            CoreError::NotFound(m) => write!(f, "not found: {m}"),
            CoreError::AlreadyExists(m) => write!(f, "already exists: {m}"),
            CoreError::NoProject => write!(f, "no openspec/ project found"),
        }
    }
}

impl std::error::Error for CoreError {}

impl From<std::io::Error> for CoreError {
    fn from(e: std::io::Error) -> Self {
        CoreError::Io(e.to_string())
    }
}
impl From<ParseError> for CoreError {
    fn from(e: ParseError) -> Self {
        CoreError::Parse(e)
    }
}
impl From<MergeError> for CoreError {
    fn from(e: MergeError) -> Self {
        CoreError::Merge(e)
    }
}
impl From<YamlError> for CoreError {
    fn from(e: YamlError) -> Self {
        CoreError::Yaml(e)
    }
}

/// Convenience alias.
pub type Result<T> = std::result::Result<T, CoreError>;
