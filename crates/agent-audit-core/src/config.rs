// SPDX-License-Identifier: Apache-2.0

use agent_audit_hosts::{canonical_host_profile, HOST_PROFILES};
use agent_audit_rules::{rule_metadata, RuleExecutionMode, RuleStatus};
use serde::Deserialize;

use crate::error::{AuditError, AuditResult};
use crate::model::{AuditMethodologyMetadata, Severity};
use crate::text_utils::normalized_match_text;

pub const CONFIG_FILENAME: &str = ".agent-audit.yaml";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditConfig {
    pub profiles: Vec<String>,
    pub fail_on: Vec<Severity>,
    pub rule_mode: RuleExecutionMode,
    pub ignore: Vec<ConfigIgnoreEntry>,
    pub methodology: Option<AuditMethodologyMetadata>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigIgnoreEntry {
    pub rule: String,
    pub path: Option<String>,
    pub match_value: Option<String>,
    pub reason: String,
}

impl AuditConfig {
    pub fn empty() -> Self {
        Self {
            profiles: Vec::new(),
            fail_on: Vec::new(),
            rule_mode: RuleExecutionMode::Default,
            ignore: Vec::new(),
            methodology: None,
        }
    }
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    #[serde(default)]
    profiles: Option<Vec<String>>,
    #[serde(default)]
    fail_on: Option<Vec<String>>,
    #[serde(default)]
    rule_mode: Option<String>,
    #[serde(default)]
    ignore: Option<Vec<RawIgnoreEntry>>,
    #[serde(default)]
    methodology: Option<RawMethodologyConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawIgnoreEntry {
    rule: Option<String>,
    path: Option<String>,
    #[serde(rename = "match")]
    match_value: Option<String>,
    reason: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawMethodologyConfig {
    corpus_name: Option<String>,
    corpus_entry_id: Option<String>,
    methodology_version: Option<String>,
    #[serde(default)]
    inclusion_tags: Option<Vec<String>>,
    repo_classification: Option<String>,
    scan_batch_id: Option<String>,
}

pub fn parse_audit_config(content: &str) -> AuditResult<AuditConfig> {
    let raw = serde_yaml::from_str::<Option<RawConfig>>(content)
        .map_err(|source| AuditError::ConfigParse {
            filename: CONFIG_FILENAME,
            source,
        })?
        .unwrap_or_default();

    let profiles = validate_profiles(raw.profiles.unwrap_or_default())?;
    let fail_on = validate_fail_on(raw.fail_on.unwrap_or_default())?;
    let rule_mode = validate_rule_mode(raw.rule_mode)?;
    let ignore = validate_ignore(raw.ignore.unwrap_or_default())?;
    let methodology = validate_methodology(raw.methodology)?;

    Ok(AuditConfig {
        profiles,
        fail_on,
        rule_mode,
        ignore,
        methodology,
    })
}

fn validate_profiles(profiles: Vec<String>) -> AuditResult<Vec<String>> {
    profiles
        .into_iter()
        .enumerate()
        .map(|(index, profile)| {
            let profile = profile.trim();
            if let Some(canonical_profile) = canonical_host_profile(profile) {
                Ok(canonical_profile.to_owned())
            } else {
                Err(validation_error(format!(
                    "profiles[{index}] uses unknown host profile `{profile}`; expected one of: {}",
                    HOST_PROFILES.join(", ")
                )))
            }
        })
        .collect()
}

fn validate_fail_on(severities: Vec<String>) -> AuditResult<Vec<Severity>> {
    severities
        .into_iter()
        .enumerate()
        .map(|(index, severity)| {
            let severity = severity.trim();
            parse_severity(severity).ok_or_else(|| {
                validation_error(format!(
                    "fail_on[{index}] uses unknown severity `{severity}`; expected one of: info, low, medium, high, critical"
                ))
            })
        })
        .collect()
}

fn validate_rule_mode(mode: Option<String>) -> AuditResult<RuleExecutionMode> {
    let Some(mode) = mode
        .as_deref()
        .map(str::trim)
        .filter(|mode| !mode.is_empty())
    else {
        return Ok(RuleExecutionMode::Default);
    };

    RuleExecutionMode::parse(mode).ok_or_else(|| {
        validation_error(format!(
            "rule_mode uses unknown mode `{mode}`; expected one of: default, strict, research"
        ))
    })
}

fn validate_ignore(entries: Vec<RawIgnoreEntry>) -> AuditResult<Vec<ConfigIgnoreEntry>> {
    entries
        .into_iter()
        .enumerate()
        .map(|(index, entry)| validate_ignore_entry(index, entry))
        .collect()
}

fn validate_ignore_entry(index: usize, entry: RawIgnoreEntry) -> AuditResult<ConfigIgnoreEntry> {
    let rule = required_non_empty_field(entry.rule.as_deref(), index, "rule")?;
    match rule_metadata(rule) {
        Some(metadata) if metadata.status == RuleStatus::Active => {}
        Some(_) => {
            return Err(validation_error(format!(
                "ignore[{index}].rule uses reserved rule ID `{rule}`; reserved rules are not emitted and cannot be suppressed yet"
            )));
        }
        None => {
            return Err(validation_error(format!(
                "ignore[{index}].rule uses unknown rule ID `{rule}`; expected an active rule ID"
            )));
        }
    }

    let path = entry
        .path
        .as_deref()
        .map(|raw_path| {
            let raw_path = required_non_empty_field(Some(raw_path), index, "path")?;
            validate_ignore_path(index, raw_path)
        })
        .transpose()?;
    let match_value = entry
        .match_value
        .as_deref()
        .map(|raw_match| required_non_empty_field(Some(raw_match), index, "match"))
        .transpose()?
        .map(normalize_ignore_match);

    if path.is_none() && match_value.is_none() {
        return Err(validation_error(format!(
            "ignore[{index}] must include either path or match"
        )));
    }

    let reason = required_non_empty_field(entry.reason.as_deref(), index, "reason")?;

    Ok(ConfigIgnoreEntry {
        rule: rule.to_owned(),
        path,
        match_value,
        reason: reason.to_owned(),
    })
}

fn validate_methodology(
    raw: Option<RawMethodologyConfig>,
) -> AuditResult<Option<AuditMethodologyMetadata>> {
    let Some(raw) = raw else {
        return Ok(None);
    };

    let mut metadata = AuditMethodologyMetadata {
        corpus_name: optional_trimmed_string(raw.corpus_name),
        corpus_entry_id: optional_trimmed_string(raw.corpus_entry_id),
        methodology_version: optional_trimmed_string(raw.methodology_version),
        inclusion_tags: validate_inclusion_tags(raw.inclusion_tags.unwrap_or_default())?,
        repo_classification: optional_trimmed_string(raw.repo_classification),
        scan_batch_id: optional_trimmed_string(raw.scan_batch_id),
    };

    normalize_methodology_tags(&mut metadata.inclusion_tags);

    if metadata.is_empty() {
        Ok(None)
    } else {
        Ok(Some(metadata))
    }
}

fn optional_trimmed_string(value: Option<String>) -> Option<String> {
    value
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn validate_inclusion_tags(tags: Vec<String>) -> AuditResult<Vec<String>> {
    tags.into_iter()
        .enumerate()
        .map(|(index, tag)| {
            let tag = tag.trim();
            if tag.is_empty() {
                return Err(validation_error(format!(
                    "methodology.inclusion_tags[{index}] must be a non-empty string"
                )));
            }
            Ok(tag.to_owned())
        })
        .collect()
}

fn normalize_methodology_tags(tags: &mut Vec<String>) {
    tags.sort();
    tags.dedup();
}

fn required_non_empty_field<'a>(
    value: Option<&'a str>,
    index: usize,
    field: &str,
) -> AuditResult<&'a str> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Err(validation_error(format!(
            "ignore[{index}].{field} must be a non-empty string"
        )));
    };

    Ok(value)
}

fn validate_ignore_path(index: usize, path: &str) -> AuditResult<String> {
    if is_absolute_path(path) {
        return Err(validation_error(format!(
            "ignore[{index}].path must be relative and stay inside the scanned project"
        )));
    }
    if has_parent_component(path) {
        return Err(validation_error(format!(
            "ignore[{index}].path must not contain parent traversal (`..`) components"
        )));
    }

    Ok(path.replace('\\', "/"))
}

fn normalize_ignore_match(value: &str) -> String {
    normalized_match_text(value)
}

pub fn parse_severity(value: &str) -> Option<Severity> {
    match value {
        "info" => Some(Severity::Info),
        "low" => Some(Severity::Low),
        "medium" => Some(Severity::Medium),
        "high" => Some(Severity::High),
        "critical" => Some(Severity::Critical),
        _ => None,
    }
}

fn is_absolute_path(path: &str) -> bool {
    path.starts_with('/') || path.starts_with('\\') || has_windows_drive_prefix(path)
}

fn has_windows_drive_prefix(path: &str) -> bool {
    let bytes = path.as_bytes();
    matches!(bytes, [drive, b':', ..] if drive.is_ascii_alphabetic())
}

fn has_parent_component(path: &str) -> bool {
    path.split(['/', '\\']).any(|component| component == "..")
}

fn validation_error(message: String) -> AuditError {
    AuditError::ConfigValidation {
        filename: CONFIG_FILENAME,
        message,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phase2_valid_config_fixtures_parse_deterministically() {
        let full = parse(include_str!(
            "../../../fixtures/spec/phase2/config/valid/full.agent-audit.yaml"
        ));
        let empty = parse(include_str!(
            "../../../fixtures/spec/phase2/config/valid/empty.agent-audit.yaml"
        ));

        assert_eq!(full.profiles, vec!["codex", "generic"]);
        assert_eq!(full.fail_on, vec![Severity::Low, Severity::High]);
        assert_eq!(full.rule_mode, RuleExecutionMode::Default);
        assert_eq!(
            full.ignore,
            vec![ConfigIgnoreEntry {
                rule: "SKILL010".to_owned(),
                path: Some("skills/legacy/SKILL.md".to_owned()),
                match_value: None,
                reason: "Legacy fixture intentionally keeps a stale reference.".to_owned(),
            }]
        );
        assert_eq!(empty, AuditConfig::empty());
    }

    #[test]
    fn phase2_invalid_config_fixtures_return_actionable_errors() {
        let cases = [
            (
                include_str!(
                    "../../../fixtures/spec/phase2/config/invalid/unknown-profile.agent-audit.yaml"
                ),
                "unknown host profile `unknown-host`",
            ),
            (
                include_str!(
                    "../../../fixtures/spec/phase2/config/invalid/unknown-severity.agent-audit.yaml"
                ),
                "unknown severity `warning`",
            ),
            (
                include_str!(
                    "../../../fixtures/spec/phase2/config/invalid/absolute-ignore-path.agent-audit.yaml"
                ),
                "path must be relative and stay inside the scanned project",
            ),
        ];

        for (content, expected) in cases {
            let error = parse_error(content);

            assert!(
                error.to_string().contains(expected),
                "expected `{}` to contain `{}`",
                error,
                expected
            );
        }
    }

    #[test]
    fn parses_valid_config_and_normalizes_ignore_paths() {
        let config = parse(
            r#"
profiles:
  - codex
  - generic
fail_on:
  - medium
  - high
rule_mode: strict
ignore:
  - rule: SKILL010
    path: skills\reviewer\SKILL.md
    reason: Accepted compatibility fixture.
"#,
        );

        assert_eq!(config.profiles, vec!["codex", "generic"]);
        assert_eq!(config.fail_on, vec![Severity::Medium, Severity::High]);
        assert_eq!(config.rule_mode, RuleExecutionMode::Strict);
        assert_eq!(
            config.ignore,
            vec![ConfigIgnoreEntry {
                rule: "SKILL010".to_owned(),
                path: Some("skills/reviewer/SKILL.md".to_owned()),
                match_value: None,
                reason: "Accepted compatibility fixture.".to_owned(),
            }]
        );
    }

    #[test]
    fn parses_profile_aliases_as_canonical_profiles() {
        let config = parse(
            r#"
profiles:
  - spec
  - claude
  - copilot
  - codex
"#,
        );

        assert_eq!(
            config.profiles,
            vec![
                "agent-skills-spec",
                "claude-code",
                "github-copilot",
                "codex"
            ]
        );
    }

    #[test]
    fn rejects_unknown_profile_alias_with_supported_names() {
        let error = parse_error("profiles:\n  - github\n");
        let message = error.to_string();

        assert!(message.contains("profiles[0] uses unknown host profile `github`"));
        assert!(message.contains("agent-skills-spec, claude-code, codex"));
        assert!(message.contains("github-copilot, vscode-copilot, generic"));
    }

    #[test]
    fn omitted_and_empty_fields_default_to_empty_collections() {
        assert_eq!(parse("").profiles, Vec::<String>::new());
        assert_eq!(parse("{}").fail_on, Vec::<Severity>::new());
        assert!(parse("profiles:\nfail_on:\nignore:\n").ignore.is_empty());
        assert_eq!(parse("").rule_mode, RuleExecutionMode::Default);
        assert_eq!(parse("rule_mode:\n").rule_mode, RuleExecutionMode::Default);
    }

    #[test]
    fn parses_rule_execution_modes() {
        assert_eq!(
            parse("rule_mode: default\n").rule_mode,
            RuleExecutionMode::Default
        );
        assert_eq!(
            parse("rule_mode: strict\n").rule_mode,
            RuleExecutionMode::Strict
        );
        assert_eq!(
            parse("rule_mode: research\n").rule_mode,
            RuleExecutionMode::Research
        );
        assert_eq!(
            parse("rule_mode: ' research '\n").rule_mode,
            RuleExecutionMode::Research
        );
    }

    #[test]
    fn rejects_unknown_rule_execution_mode() {
        let error = parse_error("rule_mode: experimental\n");

        assert_validation_contains(
            error,
            "rule_mode uses unknown mode `experimental`; expected one of: default, strict, research",
        );
    }

    #[test]
    fn rejects_malformed_yaml() {
        let error = parse_error("profiles: [codex");

        assert!(matches!(error, AuditError::ConfigParse { .. }));
        assert!(error
            .to_string()
            .contains("failed to parse .agent-audit.yaml"));
    }

    #[test]
    fn rejects_unknown_top_level_fields() {
        let error = parse_error("profile: codex\n");

        assert!(matches!(error, AuditError::ConfigParse { .. }));
        assert!(error.to_string().contains("unknown field"));
        assert!(error.to_string().contains("profile"));
    }

    #[test]
    fn rejects_supply_chain_config_control() {
        let error = parse_error("supply_chain:\n  policy: strict\n");
        let message = error.to_string();

        assert!(
            matches!(error, AuditError::ConfigParse { .. }),
            "expected parse error, got {error:?}"
        );
        assert!(message.contains("unknown field `supply_chain`"));
    }

    #[test]
    fn parses_optional_methodology_metadata() {
        let config = parse(
            r#"
methodology:
  corpus_name: " v0.8 public audit "
  corpus_entry_id: " repo-001 "
  methodology_version: " 2026-05 "
  inclusion_tags:
    - " executable "
    - " public "
    - " executable "
  repo_classification: " oss-skill-repo "
  scan_batch_id: " batch-2026-05 "
"#,
        );
        let methodology = config.methodology.expect("methodology metadata");

        assert_eq!(
            methodology.corpus_name.as_deref(),
            Some("v0.8 public audit")
        );
        assert_eq!(methodology.corpus_entry_id.as_deref(), Some("repo-001"));
        assert_eq!(methodology.methodology_version.as_deref(), Some("2026-05"));
        assert_eq!(methodology.inclusion_tags, vec!["executable", "public"]);
        assert_eq!(
            methodology.repo_classification.as_deref(),
            Some("oss-skill-repo")
        );
        assert_eq!(methodology.scan_batch_id.as_deref(), Some("batch-2026-05"));
    }

    #[test]
    fn empty_methodology_metadata_is_absent() {
        let config = parse(
            r#"
methodology:
  corpus_name: " "
  inclusion_tags:
"#,
        );

        assert_eq!(config.methodology, None);
    }

    #[test]
    fn rejects_blank_methodology_inclusion_tag() {
        let error = parse_error(
            r#"
methodology:
  inclusion_tags:
    - public
    - " "
"#,
        );

        assert_validation_contains(
            error,
            "methodology.inclusion_tags[1] must be a non-empty string",
        );
    }

    #[test]
    fn rejects_unknown_profile() {
        let error = parse_error("profiles:\n  - unknown-host\n");

        assert_validation_contains(error, "unknown host profile `unknown-host`");
    }

    #[test]
    fn rejects_unknown_severity() {
        let error = parse_error("fail_on:\n  - warning\n");

        assert_validation_contains(error, "unknown severity `warning`");
    }

    #[test]
    fn parses_known_severities_exactly() {
        assert_eq!(parse_severity("info"), Some(Severity::Info));
        assert_eq!(parse_severity("low"), Some(Severity::Low));
        assert_eq!(parse_severity("medium"), Some(Severity::Medium));
        assert_eq!(parse_severity("high"), Some(Severity::High));
        assert_eq!(parse_severity("critical"), Some(Severity::Critical));
        assert_eq!(parse_severity("Low"), None);
        assert_eq!(parse_severity("warning"), None);
    }

    #[test]
    fn rejects_unknown_ignore_rule() {
        let error = parse_error(
            r#"
ignore:
  - rule: SEC999
    path: SKILL.md
    reason: Not currently supported.
"#,
        );

        assert_validation_contains(error, "unknown rule ID `SEC999`");
    }

    #[test]
    fn rejects_reserved_ignore_rule_in_all_rule_execution_modes() {
        for mode in ["default", "strict", "research"] {
            let error = parse_error(&format!(
                r#"
rule_mode: {mode}
ignore:
  - rule: SEC004
    path: scripts/install.sh
    reason: Reviewed reserved rule fixture.
"#
            ));

            assert_validation_contains(
                error,
                "ignore[0].rule uses reserved rule ID `SEC004`; reserved rules are not emitted and cannot be suppressed yet",
            );
        }
    }

    #[test]
    fn accepts_active_skill050_ignore_rule() {
        let config = parse(
            r#"
ignore:
  - rule: SKILL050
    path: SKILL.md
    reason: "Accepted risk: target host accepts this metadata under a reviewed profile exception."
"#,
        );

        assert_eq!(
            config.ignore,
            vec![ConfigIgnoreEntry {
                rule: "SKILL050".to_owned(),
                path: Some("SKILL.md".to_owned()),
                match_value: None,
                reason:
                    "Accepted risk: target host accepts this metadata under a reviewed profile exception."
                        .to_owned(),
            }]
        );
    }

    #[test]
    fn rejects_missing_and_blank_ignore_reason() {
        let missing = parse_error(
            r#"
ignore:
  - rule: SKILL010
    path: SKILL.md
"#,
        );
        let blank = parse_error(
            r#"
ignore:
  - rule: SKILL010
    path: SKILL.md
    reason: " "
"#,
        );

        assert_validation_contains(missing, "ignore[0].reason must be a non-empty string");
        assert_validation_contains(blank, "ignore[0].reason must be a non-empty string");
    }

    #[test]
    fn rejects_missing_and_blank_ignore_path() {
        let missing = parse_error(
            r#"
ignore:
  - rule: SKILL010
    reason: Accepted fixture.
"#,
        );
        let blank = parse_error(
            r#"
ignore:
  - rule: SKILL010
    path: " "
    reason: Accepted fixture.
"#,
        );

        assert_validation_contains(missing, "ignore[0] must include either path or match");
        assert_validation_contains(blank, "ignore[0].path must be a non-empty string");
    }

    #[test]
    fn parses_match_suppressions_without_path() {
        let config = parse(
            r#"
ignore:
  - rule: SKILL040
    match: " frontmatter_field=requires "
    reason: Accepted compatibility metadata across generated skills.
"#,
        );

        assert_eq!(
            config.ignore,
            vec![ConfigIgnoreEntry {
                rule: "SKILL040".to_owned(),
                path: None,
                match_value: Some("frontmatter_field=requires".to_owned()),
                reason: "Accepted compatibility metadata across generated skills.".to_owned(),
            }]
        );
    }

    #[test]
    fn rejects_missing_and_blank_ignore_match_when_path_is_absent() {
        let missing = parse_error(
            r#"
ignore:
  - rule: SKILL040
    reason: Accepted fixture.
"#,
        );
        let blank = parse_error(
            r#"
ignore:
  - rule: SKILL040
    match: " "
    reason: Accepted fixture.
"#,
        );

        assert_validation_contains(missing, "ignore[0] must include either path or match");
        assert_validation_contains(blank, "ignore[0].match must be a non-empty string");
    }

    #[test]
    fn rejects_absolute_ignore_paths() {
        for path in ["/SKILL.md", r"\SKILL.md", r"C:\skills\SKILL.md"] {
            let error = parse_error(&format!(
                r#"
ignore:
  - rule: SKILL010
    path: '{path}'
    reason: Accepted fixture.
"#
            ));

            assert_validation_contains(
                error,
                "ignore[0].path must be relative and stay inside the scanned project",
            );
        }
    }

    #[test]
    fn rejects_parent_traversal_ignore_paths() {
        for path in ["../SKILL.md", "skills/../SKILL.md", r"skills\..\SKILL.md"] {
            let error = parse_error(&format!(
                r#"
ignore:
  - rule: SKILL010
    path: '{path}'
    reason: Accepted fixture.
"#
            ));

            assert_validation_contains(
                error,
                "ignore[0].path must not contain parent traversal (`..`) components",
            );
        }
    }

    #[test]
    fn trims_scalar_values_before_validation() {
        let config = parse(
            r#"
profiles:
  - " codex "
fail_on:
  - " low "
ignore:
  - rule: " SKILL010 "
    path: ' skills\SKILL.md '
    reason: " Accepted fixture. "
"#,
        );

        assert_eq!(config.profiles, vec!["codex"]);
        assert_eq!(config.fail_on, vec![Severity::Low]);
        assert_eq!(config.ignore[0].rule, "SKILL010");
        assert_eq!(config.ignore[0].path.as_deref(), Some("skills/SKILL.md"));
        assert_eq!(config.ignore[0].match_value, None);
        assert_eq!(config.ignore[0].reason, "Accepted fixture.");
    }

    fn parse(content: &str) -> AuditConfig {
        parse_audit_config(content).expect("valid config")
    }

    fn parse_error(content: &str) -> AuditError {
        parse_audit_config(content).expect_err("invalid config")
    }

    fn assert_validation_contains(error: AuditError, expected: &str) {
        assert!(
            matches!(error, AuditError::ConfigValidation { .. }),
            "expected validation error, got {error:?}"
        );
        assert!(
            error.to_string().contains(expected),
            "expected `{}` to contain `{}`",
            error,
            expected
        );
    }
}
