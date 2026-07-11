//! Parsing OpenSpec markdown into the [`crate::model`] types.
//!
//! # Fidelity rules
//!
//! The parser is **fence-aware**: a `#`-prefixed line is treated as a
//! structural heading only when it appears at column 0 **and** outside a fenced
//! code block (` ``` ` or `~~~`). This is essential because real spec bodies
//! embed examples such as `### Requirement: Old Name` and
//! `## RENAMED Requirements` *inside* code fences — those must be preserved as
//! body text, never mistaken for structure.
//!
//! Non-structural prose (title lead-in, trailing sections, requirement
//! descriptions, scenario bodies) is captured verbatim so it survives a
//! parse → render → parse round-trip as a stable model (canonical-form
//! idempotence; see [`crate::render`]).

use crate::model::{DeltaSpec, Removed, Rename, Requirement, Scenario, Spec};
use std::fmt;

/// An error encountered while parsing OpenSpec markdown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// The document did not begin with a `# Title` heading.
    MissingTitle,
    /// A requirement header carried no name (`### Requirement:` with empty text).
    EmptyRequirementName,
    /// A scenario header carried no name (`#### Scenario:` with empty text).
    EmptyScenarioName,
    /// A `RENAMED` section had a `FROM`/`TO` line that could not be parsed.
    MalformedRename(String),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::MissingTitle => write!(f, "spec is missing a `# Title` heading"),
            ParseError::EmptyRequirementName => {
                write!(f, "found a `### Requirement:` header with no name")
            }
            ParseError::EmptyScenarioName => {
                write!(f, "found a `#### Scenario:` header with no name")
            }
            ParseError::MalformedRename(l) => write!(f, "malformed RENAMED entry: {l}"),
        }
    }
}

impl std::error::Error for ParseError {}

/// A classified structural heading discovered outside code fences at column 0.
#[derive(Debug, Clone, Copy)]
struct Heading<'a> {
    level: usize,
    text: &'a str,
}

/// Classify every line of `input`, returning the raw lines alongside an
/// optional [`Heading`] for lines that are structural headings.
///
/// Fence state is tracked so headings inside code blocks are reported as `None`.
fn classify(input: &str) -> (Vec<&str>, Vec<Option<Heading<'_>>>) {
    let lines: Vec<&str> = input.split('\n').collect();
    let mut headings: Vec<Option<Heading<'_>>> = Vec::with_capacity(lines.len());
    // `Some((fence_char, fence_len))` while inside a fenced code block.
    let mut fence: Option<(char, usize)> = None;

    for line in &lines {
        if let Some(marker) = fence_marker(line) {
            match fence {
                None => {
                    fence = Some(marker);
                    headings.push(None);
                    continue;
                }
                Some((open_char, open_len)) => {
                    // A closing fence matches the opening char, is at least as
                    // long, and carries no info string.
                    let (mc, mlen, has_info) = marker_info(line);
                    if mc == open_char && mlen >= open_len && !has_info {
                        fence = None;
                    }
                    headings.push(None);
                    continue;
                }
            }
        }
        if fence.is_some() {
            headings.push(None);
            continue;
        }
        headings.push(heading_at_col0(line));
    }
    (lines, headings)
}

/// If `line` is a fence delimiter (3+ backticks or tildes, optionally indented
/// up to 3 spaces), return its `(char, run_length)`.
fn fence_marker(line: &str) -> Option<(char, usize)> {
    let indent = line.len() - line.trim_start_matches(' ').len();
    if indent > 3 {
        return None;
    }
    let rest = &line[indent..];
    let first = rest.chars().next()?;
    if first != '`' && first != '~' {
        return None;
    }
    let run = rest.chars().take_while(|&c| c == first).count();
    if run >= 3 {
        Some((first, run))
    } else {
        None
    }
}

/// Return `(fence_char, run_length, has_info_string)` for a known fence line.
fn marker_info(line: &str) -> (char, usize, bool) {
    let indent = line.len() - line.trim_start_matches(' ').len();
    let rest = &line[indent..];
    let first = rest.chars().next().unwrap_or('`');
    let run = rest.chars().take_while(|&c| c == first).count();
    let after = rest[run..].trim();
    (first, run, !after.is_empty())
}

/// Detect a column-0 ATX heading (`#`..`######` followed by a space). Returns
/// `None` for indented lines, so inline/example `###` in bodies is ignored.
fn heading_at_col0(line: &str) -> Option<Heading<'_>> {
    if !line.starts_with('#') {
        return None;
    }
    let level = line.chars().take_while(|&c| c == '#').count();
    if level == 0 || level > 6 {
        return None;
    }
    let rest = &line[level..];
    // Require a space after the hashes (ATX rule); the text is the remainder.
    let text = rest.strip_prefix(' ')?;
    Some(Heading {
        level,
        text: text.trim_end(),
    })
}

/// Join a slice of raw lines and strip surrounding blank lines, preserving
/// interior blank lines.
fn trim_block(lines: &[&str]) -> String {
    let mut start = 0;
    let mut end = lines.len();
    while start < end && lines[start].trim().is_empty() {
        start += 1;
    }
    while end > start && lines[end - 1].trim().is_empty() {
        end -= 1;
    }
    lines[start..end].join("\n")
}

/// The requirement-name prefix inside a `### Requirement:` heading.
const REQ_PREFIX: &str = "Requirement:";
/// The scenario-name prefix inside a `#### Scenario:` heading.
const SCENARIO_PREFIX: &str = "Scenario:";

fn is_requirement_heading(h: &Heading<'_>) -> bool {
    h.level == 3 && h.text.trim_start().starts_with(REQ_PREFIX)
}

fn is_scenario_heading(h: &Heading<'_>) -> bool {
    h.level == 4 && h.text.trim_start().starts_with(SCENARIO_PREFIX)
}

fn requirement_name<'a>(h: Heading<'a>) -> &'a str {
    h.text.trim_start()[REQ_PREFIX.len()..].trim()
}

fn scenario_name<'a>(h: Heading<'a>) -> &'a str {
    h.text.trim_start()[SCENARIO_PREFIX.len()..].trim()
}

/// Parse a canonical capability spec (`spec.md` in `openspec/specs/<cap>/`).
pub fn parse_spec(input: &str) -> Result<Spec, ParseError> {
    let (lines, headings) = classify(input);

    // Locate the title: first structural level-1 heading.
    let title_idx = headings
        .iter()
        .position(|h| matches!(h, Some(h) if h.level == 1))
        .ok_or(ParseError::MissingTitle)?;
    let title = headings[title_idx].unwrap().text.trim().to_string();

    // The requirements region begins at the first `### Requirement:` heading.
    let first_req = (title_idx + 1..lines.len())
        .find(|&i| matches!(&headings[i], Some(h) if is_requirement_heading(h)));

    let (lead_end, req_start) = match first_req {
        Some(i) => (i, i),
        None => (lines.len(), lines.len()),
    };
    let lead = trim_block(&lines[title_idx + 1..lead_end]);

    // Requirements run until the first trailing level-2 (or level-1) heading.
    let mut i = req_start;
    let mut requirements = Vec::new();
    let mut tail_start = lines.len();
    while i < lines.len() {
        match &headings[i] {
            Some(h) if is_requirement_heading(h) => {
                let name = requirement_name(*h).to_string();
                if name.is_empty() {
                    return Err(ParseError::EmptyRequirementName);
                }
                let block_end = next_requirement_boundary(&headings, i + 1);
                let req = parse_requirement(name, &lines, &headings, i + 1, block_end)?;
                requirements.push(req);
                if block_end < lines.len()
                    && matches!(&headings[block_end], Some(h) if h.level <= 2)
                {
                    tail_start = block_end;
                    break;
                }
                i = block_end;
            }
            Some(h) if h.level <= 2 => {
                tail_start = i;
                break;
            }
            _ => i += 1,
        }
    }

    let tail = trim_block(&lines[tail_start..]);
    Ok(Spec {
        title,
        lead,
        requirements,
        tail,
    })
}

/// Find the end (exclusive) of a requirement body starting at `from`: the next
/// `### Requirement:` heading, or any level ≤ 2 heading, or EOF.
fn next_requirement_boundary(headings: &[Option<Heading<'_>>], from: usize) -> usize {
    for (offset, h) in headings[from..].iter().enumerate() {
        if let Some(h) = h {
            if is_requirement_heading(h) || h.level <= 2 {
                return from + offset;
            }
        }
    }
    headings.len()
}

/// Parse the body of one requirement (description + scenarios) spanning
/// `[start, end)`.
fn parse_requirement(
    name: String,
    lines: &[&str],
    headings: &[Option<Heading<'_>>],
    start: usize,
    end: usize,
) -> Result<Requirement, ParseError> {
    // Description runs until the first scenario heading.
    let first_scenario = (start..end)
        .find(|&i| matches!(&headings[i], Some(h) if is_scenario_heading(h)))
        .unwrap_or(end);
    let text = trim_block(&lines[start..first_scenario]);

    let mut scenarios = Vec::new();
    let mut i = first_scenario;
    while i < end {
        if let Some(h) = &headings[i] {
            if is_scenario_heading(h) {
                let sname = scenario_name(*h).to_string();
                if sname.is_empty() {
                    return Err(ParseError::EmptyScenarioName);
                }
                let body_end = (i + 1..end)
                    .find(|&j| matches!(&headings[j], Some(h) if is_scenario_heading(h)))
                    .unwrap_or(end);
                let body = trim_block(&lines[i + 1..body_end]);
                scenarios.push(Scenario { name: sname, body });
                i = body_end;
                continue;
            }
        }
        i += 1;
    }

    Ok(Requirement {
        name,
        text,
        scenarios,
    })
}

/// One of the four delta section kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SectionKind {
    Added,
    Modified,
    Removed,
    Renamed,
}

/// Match a level-2 heading against the delta section keywords (case-insensitive).
fn delta_section(h: &Heading<'_>) -> Option<SectionKind> {
    if h.level != 2 {
        return None;
    }
    let t = h.text.trim().to_ascii_lowercase();
    match t.as_str() {
        "added requirements" => Some(SectionKind::Added),
        "modified requirements" => Some(SectionKind::Modified),
        "removed requirements" => Some(SectionKind::Removed),
        "renamed requirements" => Some(SectionKind::Renamed),
        _ => None,
    }
}

/// Parse a delta spec (`spec.md` under a change's `specs/<cap>/`).
pub fn parse_delta(input: &str) -> Result<DeltaSpec, ParseError> {
    let (lines, headings) = classify(input);

    // Optional title.
    let title_idx = headings
        .iter()
        .position(|h| matches!(h, Some(h) if h.level == 1));
    let title = title_idx.map(|i| headings[i].unwrap().text.trim().to_string());

    // Lead runs from after the title (or start) to the first delta section.
    let scan_start = title_idx.map(|i| i + 1).unwrap_or(0);
    let first_section = (scan_start..lines.len())
        .find(|&i| matches!(&headings[i], Some(h) if delta_section(h).is_some()))
        .unwrap_or(lines.len());
    let lead = trim_block(&lines[scan_start..first_section]);

    let mut delta = DeltaSpec {
        title,
        lead,
        ..DeltaSpec::default()
    };

    // Walk sections.
    let mut i = first_section;
    while i < lines.len() {
        let kind = match &headings[i] {
            Some(h) => match delta_section(h) {
                Some(k) => k,
                None => {
                    i += 1;
                    continue;
                }
            },
            None => {
                i += 1;
                continue;
            }
        };
        let sec_end = (i + 1..lines.len())
            .find(|&j| matches!(&headings[j], Some(h) if delta_section(h).is_some()))
            .unwrap_or(lines.len());
        match kind {
            SectionKind::Added => {
                parse_requirement_blocks(&lines, &headings, i + 1, sec_end, &mut delta.added)?;
            }
            SectionKind::Modified => {
                parse_requirement_blocks(&lines, &headings, i + 1, sec_end, &mut delta.modified)?;
            }
            SectionKind::Removed => {
                parse_removed_blocks(&lines, &headings, i + 1, sec_end, &mut delta.removed)?;
            }
            SectionKind::Renamed => {
                parse_renames(&lines, i + 1, sec_end, &mut delta.renamed)?;
            }
        }
        i = sec_end;
    }

    Ok(delta)
}

/// Parse a run of `### Requirement:` blocks (used by ADDED and MODIFIED).
fn parse_requirement_blocks(
    lines: &[&str],
    headings: &[Option<Heading<'_>>],
    start: usize,
    end: usize,
    out: &mut Vec<Requirement>,
) -> Result<(), ParseError> {
    let mut i = start;
    while i < end {
        if let Some(h) = &headings[i] {
            if is_requirement_heading(h) {
                let name = requirement_name(*h).to_string();
                if name.is_empty() {
                    return Err(ParseError::EmptyRequirementName);
                }
                let block_end = (i + 1..end)
                    .find(|&j| matches!(&headings[j], Some(h) if is_requirement_heading(h)))
                    .unwrap_or(end);
                out.push(parse_requirement(name, lines, headings, i + 1, block_end)?);
                i = block_end;
                continue;
            }
        }
        i += 1;
    }
    Ok(())
}

/// Parse a run of `### Requirement:` blocks in a REMOVED section (name + raw body).
fn parse_removed_blocks(
    lines: &[&str],
    headings: &[Option<Heading<'_>>],
    start: usize,
    end: usize,
    out: &mut Vec<Removed>,
) -> Result<(), ParseError> {
    let mut i = start;
    while i < end {
        if let Some(h) = &headings[i] {
            if is_requirement_heading(h) {
                let name = requirement_name(*h).to_string();
                if name.is_empty() {
                    return Err(ParseError::EmptyRequirementName);
                }
                let block_end = (i + 1..end)
                    .find(|&j| matches!(&headings[j], Some(h) if is_requirement_heading(h)))
                    .unwrap_or(end);
                let body = trim_block(&lines[i + 1..block_end]);
                out.push(Removed { name, body });
                i = block_end;
                continue;
            }
        }
        i += 1;
    }
    Ok(())
}

/// Parse `- FROM:`/`- TO:` pairs in a RENAMED section.
fn parse_renames(
    lines: &[&str],
    start: usize,
    end: usize,
    out: &mut Vec<Rename>,
) -> Result<(), ParseError> {
    let mut pending_from: Option<String> = None;
    for line in &lines[start..end] {
        let t = line.trim();
        if let Some(rest) = strip_bullet_prefix(t, "FROM:") {
            pending_from = Some(clean_rename_target(rest));
        } else if let Some(rest) = strip_bullet_prefix(t, "TO:") {
            let to = clean_rename_target(rest);
            match pending_from.take() {
                Some(from) => out.push(Rename { from, to }),
                None => return Err(ParseError::MalformedRename((*line).to_string())),
            }
        }
    }
    if pending_from.is_some() {
        return Err(ParseError::MalformedRename(
            "FROM without matching TO".to_string(),
        ));
    }
    Ok(())
}

/// Strip an optional `- ` bullet and a `FROM:`/`TO:` label, returning the rest.
fn strip_bullet_prefix<'a>(line: &'a str, label: &str) -> Option<&'a str> {
    let l = line.strip_prefix("- ").unwrap_or(line);
    let l = l.strip_prefix('-').map(str::trim_start).unwrap_or(l);
    l.strip_prefix(label).map(str::trim)
}

/// Normalize a rename target: drop backticks and an optional `### Requirement:`
/// prefix, leaving the bare name.
fn clean_rename_target(s: &str) -> String {
    let s = s.trim().trim_matches('`').trim();
    let s = s.strip_prefix("###").map(str::trim_start).unwrap_or(s);
    let s = s.strip_prefix(REQ_PREFIX).map(str::trim).unwrap_or(s);
    s.trim().to_string()
}
