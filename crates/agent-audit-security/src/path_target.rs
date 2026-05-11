// SPDX-License-Identifier: Apache-2.0

/// Returns the part of a Markdown-style target before any query or fragment.
///
/// This is intentionally lexical and does not parse URLs. Callers can use it
/// before checking whether a reference points at a local package-relative path.
pub fn strip_query_and_fragment(target: &str) -> &str {
    match (target.find('?'), target.find('#')) {
        (Some(query), Some(fragment)) => &target[..query.min(fragment)],
        (Some(index), None) | (None, Some(index)) => &target[..index],
        (None, None) => target,
    }
}

/// Returns true when `target` begins with an RFC-style URI scheme.
///
/// A colon after a forward slash or backslash is treated as part of a path, not
/// a scheme. Windows drive prefixes still match this function, so callers that
/// need to distinguish them should check [`has_windows_prefix`] first.
pub fn has_uri_scheme(target: &str) -> bool {
    let Some(colon_index) = target.find(':') else {
        return false;
    };
    if target[..colon_index].contains(['/', '\\']) {
        return false;
    }

    let mut chars = target[..colon_index].chars();
    matches!(chars.next(), Some(first) if first.is_ascii_alphabetic())
        && chars.all(|value| value.is_ascii_alphanumeric() || matches!(value, '+' | '-' | '.'))
}

/// Returns true for Windows drive prefixes and UNC-style network path prefixes.
pub fn has_windows_prefix(target: &str) -> bool {
    let bytes = target.as_bytes();
    matches!(
        bytes,
        [drive, b':', ..] if drive.is_ascii_alphabetic()
    ) || target.starts_with(r"\\")
        || target.starts_with("//")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_query_or_fragment_at_the_first_marker() {
        assert_eq!(
            strip_query_and_fragment("references/guide.md?raw=1#setup"),
            "references/guide.md"
        );
        assert_eq!(
            strip_query_and_fragment("assets/icon.png#preview?raw=1"),
            "assets/icon.png"
        );
        assert_eq!(strip_query_and_fragment("scripts/run.sh"), "scripts/run.sh");
    }

    #[test]
    fn detects_portable_uri_schemes_without_confusing_path_colons() {
        for target in [
            "https://example.test/file",
            "mailto:security@example.test",
            "urn:isbn:9780143127796",
            "vscode+agent.file://example",
        ] {
            assert!(has_uri_scheme(target), "{target}");
        }

        for target in [
            "references/key:value.md",
            r"references\key:value.md",
            "1https://example.test",
            "agent_skill://example.test",
            ":missing-scheme",
        ] {
            assert!(!has_uri_scheme(target), "{target}");
        }
    }

    #[test]
    fn detects_windows_drive_and_unc_prefixes() {
        for target in [
            "C:/Users/Ada/skill.md",
            r"c:\Users\Ada\skill.md",
            "Z:",
            r"\\server\share\skill.md",
            "//server/share/skill.md",
        ] {
            assert!(has_windows_prefix(target), "{target}");
        }

        for target in ["/absolute/path", r"\absolute\path", "references/C:/note.md"] {
            assert!(!has_windows_prefix(target), "{target}");
        }
    }
}
