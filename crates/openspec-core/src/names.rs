//! Identifier validation for change and capability names.
//!
//! Change and capability names become path components (`changes/<name>/`,
//! `specs/<cap>/`, `.mpd/state/<name>.json`). Because those names can arrive
//! from untrusted sources — a git-tracked `.mpd/current`, a `--change` flag,
//! model output parsed from markdown — they MUST be validated at every boundary
//! where they enter, not only at creation, to prevent path traversal (CWE-22).

/// The shared kebab-case rule: starts with a lowercase letter, then only
/// `a-z`, `0-9`, and single `-` separators; no leading digit, no `_`, no `..`,
/// no path separators, no trailing/doubled `-`.
pub fn validate_name(kind: &str, name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err(format!("{kind} name is empty"));
    }
    let first = name.chars().next().unwrap();
    if !first.is_ascii_lowercase() {
        return Err(format!("{kind} name must start with a lowercase letter"));
    }
    if name.ends_with('-') {
        return Err(format!("{kind} name must not end with '-'"));
    }
    if name.contains("--") {
        return Err(format!("{kind} name must not contain '--'"));
    }
    for c in name.chars() {
        if !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') {
            return Err(format!(
                "{kind} name may only contain a-z, 0-9, and '-' (found {c:?})"
            ));
        }
    }
    Ok(())
}

/// Validate a change name.
pub fn validate_change_name(name: &str) -> Result<(), String> {
    validate_name("change", name)
}

/// Validate a capability name.
pub fn validate_capability_name(name: &str) -> Result<(), String> {
    validate_name("capability", name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_traversal_and_separators() {
        assert!(validate_change_name("../etc").is_err());
        assert!(validate_change_name("a/b").is_err());
        assert!(validate_change_name("..").is_err());
        assert!(validate_change_name("a..b").is_err());
        assert!(validate_change_name(".hidden").is_err());
    }

    #[test]
    fn accepts_kebab() {
        assert!(validate_change_name("add-rate-limiter").is_ok());
        assert!(validate_capability_name("user-auth").is_ok());
    }
}
