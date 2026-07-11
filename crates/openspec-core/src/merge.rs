//! Applying a [`DeltaSpec`] to a [`Spec`] — the archive-time merge.
//!
//! The algorithm and its ordering are fixed by the OpenSpec conventions
//! (`openspec-conventions` spec, "Archive Process Enhancement"):
//!
//! 1. Apply **RENAMED** first (so later sections can reference new names).
//! 2. Apply **REMOVED** by normalized-header match.
//! 3. Apply **MODIFIED** by normalized-header match (using new names if renamed).
//! 4. Apply **ADDED**, appending new requirements.
//!
//! Matching normalizes a header by trimming and compares case-sensitively.
//! Every operation is validated *before* mutation is observable to the caller:
//! MODIFIED/REMOVED/RENAMED-from headers must exist, ADDED and RENAMED-to
//! headers must not collide. Any violation aborts the whole merge.

use crate::model::{DeltaSpec, Spec};
use std::collections::HashSet;
use std::fmt;

/// Counts of each delta operation applied by a successful [`merge`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MergeStats {
    /// Requirements appended.
    pub added: usize,
    /// Requirements replaced.
    pub modified: usize,
    /// Requirements removed.
    pub removed: usize,
    /// Requirements renamed.
    pub renamed: usize,
}

/// A reason a merge could not be applied. All variants abort the merge with no
/// partial mutation visible to the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MergeError {
    /// The base spec already contained a duplicate requirement header.
    DuplicateInBase(String),
    /// A `RENAMED` `FROM` header does not exist in the base spec.
    RenameSourceMissing(String),
    /// A `RENAMED` `TO` header collides with an existing requirement.
    RenameTargetConflict(String),
    /// A `REMOVED` header does not exist in the base spec.
    RemovedMissing(String),
    /// A `MODIFIED` header does not exist in the base spec.
    ModifiedMissing(String),
    /// An `ADDED` header already exists in the base spec.
    AddedConflict(String),
}

impl fmt::Display for MergeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use MergeError::*;
        match self {
            DuplicateInBase(h) => write!(f, "base spec has duplicate requirement header: {h:?}"),
            RenameSourceMissing(h) => write!(f, "cannot rename: no requirement named {h:?}"),
            RenameTargetConflict(h) => {
                write!(
                    f,
                    "cannot rename to {h:?}: a requirement by that name exists"
                )
            }
            RemovedMissing(h) => write!(f, "cannot remove: no requirement named {h:?}"),
            ModifiedMissing(h) => write!(f, "cannot modify: no requirement named {h:?}"),
            AddedConflict(h) => write!(f, "cannot add {h:?}: a requirement by that name exists"),
        }
    }
}

impl std::error::Error for MergeError {}

/// Position of the requirement whose normalized key equals `key`, if any.
fn find(spec: &Spec, key: &str) -> Option<usize> {
    spec.requirements.iter().position(|r| r.key() == key)
}

/// Ensure the spec has no duplicate requirement headers.
fn assert_unique(spec: &Spec, on_dup: impl Fn(String) -> MergeError) -> Result<(), MergeError> {
    let mut seen = HashSet::new();
    for req in &spec.requirements {
        if !seen.insert(req.key().to_string()) {
            return Err(on_dup(req.key().to_string()));
        }
    }
    Ok(())
}

/// Apply `delta` to `base`, returning the merged spec and operation counts.
///
/// For a brand-new capability, pass an empty base (see
/// [`crate::project::empty_spec`]); only ADDED operations will apply.
pub fn merge(base: &Spec, delta: &DeltaSpec) -> Result<(Spec, MergeStats), MergeError> {
    assert_unique(base, MergeError::DuplicateInBase)?;
    let mut result = base.clone();
    let mut stats = MergeStats::default();

    // 1. RENAMED
    for rename in &delta.renamed {
        let from = rename.from.trim();
        let to = rename.to.trim();
        let idx =
            find(&result, from).ok_or_else(|| MergeError::RenameSourceMissing(from.into()))?;
        if to != from && find(&result, to).is_some() {
            return Err(MergeError::RenameTargetConflict(to.into()));
        }
        result.requirements[idx].name = to.to_string();
        stats.renamed += 1;
    }

    // 2. REMOVED
    for removed in &delta.removed {
        let key = removed.key();
        let idx = find(&result, key).ok_or_else(|| MergeError::RemovedMissing(key.into()))?;
        result.requirements.remove(idx);
        stats.removed += 1;
    }

    // 3. MODIFIED
    for modified in &delta.modified {
        let key = modified.key();
        let idx = find(&result, key).ok_or_else(|| MergeError::ModifiedMissing(key.into()))?;
        result.requirements[idx] = modified.clone();
        stats.modified += 1;
    }

    // 4. ADDED
    for added in &delta.added {
        let key = added.key();
        if find(&result, key).is_some() {
            return Err(MergeError::AddedConflict(key.into()));
        }
        result.requirements.push(added.clone());
        stats.added += 1;
    }

    // Defensive: the result must still have unique headers.
    assert_unique(&result, MergeError::AddedConflict)?;
    Ok((result, stats))
}
