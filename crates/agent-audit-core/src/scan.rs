// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::path::Path;

use crate::config::{AuditConfig, ConfigIgnoreEntry};
use crate::discovery::discover_skill_manifests;
use crate::error::{AuditError, AuditResult};
use crate::model::{
    CompatibilityMatrix, ScanReport, ScanSummary, SkillArtifactKind, SkillCompatibilityRow,
    SkillFile, SkillFileKind, SkillFinding, SkillGraph, SkillManifest, SkillPackage,
    SkillReference, SuppressedFinding, SuppressionMatch,
};
use crate::parse::parse_skill_manifest;
use agent_audit_hosts::{
    profile_by_id, CompatibilityStatus, ProfileCompatibilityResult, HOST_PROFILES,
};
use agent_audit_rules::{
    active_rule_metadata, evaluate_structural_rules, rule_counts_as_broken_reference,
    rule_counts_as_invalid_manifest, EvaluatedRuleFinding, RuleCategory as RegistryCategory,
    RuleFrontmatterFieldFact, RuleMalformedFrontmatterFact, RuleManifestFacts, RulePackageFacts,
    RuleParsedManifestFacts, RuleReferenceFact, RuleSeverity as RegistrySeverity,
};

const UTF8_BOM: &str = "\u{feff}";

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub max_manifest_bytes: u64,
    pub config: Option<AuditConfig>,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            max_manifest_bytes: 256 * 1024,
            config: None,
        }
    }
}

pub fn scan_path(root: &Path, options: &ScanOptions) -> AuditResult<ScanReport> {
    let manifests = discover_skill_manifests(root)?;
    let profiles = selected_profiles(options.config.as_ref());
    let mut packages = Vec::new();
    let mut package_facts = Vec::new();

    for manifest_path in manifests {
        let metadata =
            std::fs::metadata(&manifest_path).map_err(|source| AuditError::Metadata {
                path: manifest_path.clone(),
                source,
            })?;
        let skill_root = manifest_path.parent().unwrap_or(root);
        let manifest_display = display_path(root, &manifest_path);

        if metadata.len() > options.max_manifest_bytes {
            package_facts.push(RulePackageFacts {
                manifest_path: manifest_display.clone(),
                manifest: RuleManifestFacts::UnreadOversized,
            });
            packages.push(SkillPackage {
                root: display_path(root, skill_root),
                manifest_path: manifest_display,
                manifest: empty_skill_manifest(),
                graph: empty_skill_graph(),
            });
            continue;
        }

        let content =
            std::fs::read_to_string(&manifest_path).map_err(|source| AuditError::Read {
                path: manifest_path.clone(),
                source,
            })?;
        let manifest = match parse_skill_manifest(&manifest_path, &content) {
            Ok(manifest) => manifest,
            Err(AuditError::Frontmatter { source, .. }) => {
                package_facts.push(RulePackageFacts {
                    manifest_path: manifest_display.clone(),
                    manifest: RuleManifestFacts::MalformedFrontmatter(
                        RuleMalformedFrontmatterFact {
                            line: source.location().map(|location| location.line() + 1),
                            parse_message: source.to_string(),
                        },
                    ),
                });
                packages.push(SkillPackage {
                    root: display_path(root, skill_root),
                    manifest_path: manifest_display,
                    manifest: empty_skill_manifest(),
                    graph: empty_skill_graph(),
                });
                continue;
            }
            Err(AuditError::FrontmatterDelimiter { line, message, .. }) => {
                package_facts.push(RulePackageFacts {
                    manifest_path: manifest_display.clone(),
                    manifest: RuleManifestFacts::MalformedFrontmatter(
                        RuleMalformedFrontmatterFact {
                            line: Some(line),
                            parse_message: message,
                        },
                    ),
                });
                packages.push(SkillPackage {
                    root: display_path(root, skill_root),
                    manifest_path: manifest_display,
                    manifest: empty_skill_manifest(),
                    graph: empty_skill_graph(),
                });
                continue;
            }
            Err(error) => return Err(error),
        };
        let frontmatter_key_lines = frontmatter_key_lines(&content);
        let mut graph = SkillGraph {
            references: resolve_references(skill_root, &manifest.links),
            artifacts: discover_artifacts(skill_root),
            files: inventory_artifact_files(skill_root)?,
        };
        graph
            .references
            .sort_by(|left, right| left.target.cmp(&right.target));

        let frontmatter_fields = manifest
            .frontmatter
            .keys()
            .filter(|field| !is_profile_accepted_frontmatter_field(&profiles, field))
            .map(|field| RuleFrontmatterFieldFact {
                name: field.clone(),
                line: frontmatter_key_lines.get(field.as_str()).copied(),
            })
            .collect();

        package_facts.push(RulePackageFacts {
            manifest_path: manifest_display.clone(),
            manifest: RuleManifestFacts::Parsed(RuleParsedManifestFacts {
                name: manifest.name.clone(),
                description: manifest.description.clone(),
                frontmatter_fields,
                references: graph
                    .references
                    .iter()
                    .map(|reference| RuleReferenceFact {
                        target: reference.target.clone(),
                        line: reference.line,
                        exists: reference.exists,
                    })
                    .collect(),
                oversized: content.len() as u64 > options.max_manifest_bytes,
            }),
        });

        packages.push(SkillPackage {
            root: display_path(root, skill_root),
            manifest_path: manifest_display,
            manifest,
            graph,
        });
    }

    let mut findings = evaluate_structural_rules(&package_facts)
        .into_iter()
        .map(skill_finding_from_evaluated_rule)
        .collect::<Vec<_>>();
    findings.extend(evaluate_compatibility_findings(
        &packages,
        options.config.as_ref(),
    ));
    sort_skill_findings(&mut findings);
    let (findings, suppressed_findings) = apply_suppressions(findings, options.config.as_ref());

    let invalid_manifest_count = findings
        .iter()
        .filter(|finding| rule_counts_as_invalid_manifest(&finding.rule_id))
        .count();
    let broken_reference_count = findings
        .iter()
        .filter(|finding| rule_counts_as_broken_reference(&finding.rule_id))
        .count();

    let compatibility =
        compatibility_matrix_for_packages(&packages, &findings, options.config.as_ref());

    Ok(ScanReport {
        summary: ScanSummary {
            package_count: packages.len(),
            finding_count: findings.len(),
            suppressed_finding_count: suppressed_findings.len(),
            invalid_manifest_count,
            broken_reference_count,
        },
        packages,
        findings,
        suppressed_findings,
        compatibility,
    })
}

fn compatibility_matrix_for_packages(
    packages: &[SkillPackage],
    findings: &[SkillFinding],
    config: Option<&AuditConfig>,
) -> CompatibilityMatrix {
    let profiles = selected_profiles(config);
    let matrix = packages
        .iter()
        .map(|package| SkillCompatibilityRow {
            path: package.manifest_path.clone(),
            name: package.manifest.name.clone(),
            profiles: profiles
                .iter()
                .map(|profile| compatibility_for_profile(profile, package, findings))
                .collect(),
        })
        .collect();

    CompatibilityMatrix { profiles, matrix }
}

fn compatibility_for_profile(
    profile: &str,
    package: &SkillPackage,
    findings: &[SkillFinding],
) -> ProfileCompatibilityResult {
    match profile {
        "agent-skills-spec" => evaluate_baseline_structural_profile(profile, package, findings),
        "claude-code" => evaluate_claude_code_profile(profile, package, findings),
        "codex" => evaluate_codex_profile(profile, package, findings),
        "github-copilot" => evaluate_github_copilot_profile(profile, package, findings),
        "generic" => evaluate_baseline_structural_profile(profile, package, findings),
        _ => ProfileCompatibilityResult {
            profile: profile.to_owned(),
            status: CompatibilityStatus::Unknown,
            finding_ids: Vec::new(),
        },
    }
}

fn evaluate_claude_code_profile(
    profile: &str,
    package: &SkillPackage,
    findings: &[SkillFinding],
) -> ProfileCompatibilityResult {
    const FAIL_RULES: &[&str] = &["SKILL001", "SKILL002", "SKILL041"];
    const BASELINE_WARN_RULES: &[&str] = &["SKILL010", "SKILL020", "SKILL030"];
    const COMPATIBILITY_WARN_RULES: &[&str] = &["SKILL050"];

    let mut rule_order = FAIL_RULES
        .iter()
        .chain(BASELINE_WARN_RULES)
        .chain(COMPATIBILITY_WARN_RULES)
        .copied()
        .collect::<Vec<_>>();
    if has_claude_unknown_frontmatter_field(package) {
        rule_order.push("SKILL040");
    }
    rule_order.sort_unstable();
    rule_order.dedup();

    let finding_ids = compatibility_finding_ids_for_package_matching(
        &package.manifest_path,
        findings,
        rule_order.iter(),
        |finding| finding.rule_id != "SKILL050" || finding.message.starts_with("Claude Code "),
    );
    let has_fail = finding_ids
        .iter()
        .any(|rule_id| FAIL_RULES.contains(&rule_id.as_str()));
    let has_matrix_warning = !is_claude_preferred_manifest_path(&package.manifest_path)
        || has_script_reference_or_artifact(package);
    let status = if has_fail {
        CompatibilityStatus::Fail
    } else if finding_ids.is_empty() && !has_matrix_warning {
        CompatibilityStatus::Pass
    } else {
        CompatibilityStatus::Warn
    };

    ProfileCompatibilityResult {
        profile: profile.to_owned(),
        status,
        finding_ids,
    }
}

fn evaluate_codex_profile(
    profile: &str,
    package: &SkillPackage,
    findings: &[SkillFinding],
) -> ProfileCompatibilityResult {
    const FAIL_RULES: &[&str] = &["SKILL001", "SKILL002", "SKILL041"];
    const BASELINE_WARN_RULES: &[&str] = &["SKILL010", "SKILL020", "SKILL030"];
    const COMPATIBILITY_WARN_RULES: &[&str] = &["SKILL050"];

    let mut rule_order = FAIL_RULES
        .iter()
        .chain(BASELINE_WARN_RULES)
        .chain(COMPATIBILITY_WARN_RULES)
        .copied()
        .collect::<Vec<_>>();
    if has_codex_unknown_frontmatter_field(package) {
        rule_order.push("SKILL040");
    }
    rule_order.sort_unstable();
    rule_order.dedup();

    let finding_ids = compatibility_finding_ids_for_package_matching(
        &package.manifest_path,
        findings,
        rule_order.iter(),
        |finding| finding.rule_id != "SKILL050" || finding.message.starts_with("Codex "),
    );
    let has_fail = finding_ids
        .iter()
        .any(|rule_id| FAIL_RULES.contains(&rule_id.as_str()));
    let has_matrix_warning = !is_codex_preferred_manifest_path(&package.manifest_path)
        || has_script_reference_or_artifact(package)
        || has_codex_permission_metadata(package);
    let status = if has_fail {
        CompatibilityStatus::Fail
    } else if finding_ids.is_empty() && !has_matrix_warning {
        CompatibilityStatus::Pass
    } else {
        CompatibilityStatus::Warn
    };

    ProfileCompatibilityResult {
        profile: profile.to_owned(),
        status,
        finding_ids,
    }
}

fn evaluate_github_copilot_profile(
    profile: &str,
    package: &SkillPackage,
    findings: &[SkillFinding],
) -> ProfileCompatibilityResult {
    const FAIL_RULES: &[&str] = &["SKILL001", "SKILL002", "SKILL041"];
    const BASELINE_WARN_RULES: &[&str] = &["SKILL010", "SKILL020", "SKILL030"];
    const COMPATIBILITY_WARN_RULES: &[&str] = &["SKILL050"];

    let mut rule_order = FAIL_RULES
        .iter()
        .chain(BASELINE_WARN_RULES)
        .chain(COMPATIBILITY_WARN_RULES)
        .copied()
        .collect::<Vec<_>>();
    if has_github_copilot_unknown_frontmatter_field(package) {
        rule_order.push("SKILL040");
    }
    rule_order.sort_unstable();
    rule_order.dedup();

    let finding_ids = compatibility_finding_ids_for_package_matching(
        &package.manifest_path,
        findings,
        rule_order.iter(),
        |finding| finding.rule_id != "SKILL050" || finding.message.starts_with("GitHub Copilot "),
    );
    let has_fail = finding_ids
        .iter()
        .any(|rule_id| FAIL_RULES.contains(&rule_id.as_str()));
    let has_matrix_warning = !is_github_copilot_preferred_manifest_path(&package.manifest_path)
        || has_script_reference_or_artifact(package)
        || has_github_copilot_unsupported_global_metadata(package);
    let status = if has_fail {
        CompatibilityStatus::Fail
    } else if finding_ids.is_empty() && !has_matrix_warning {
        CompatibilityStatus::Pass
    } else {
        CompatibilityStatus::Warn
    };

    ProfileCompatibilityResult {
        profile: profile.to_owned(),
        status,
        finding_ids,
    }
}

fn evaluate_baseline_structural_profile(
    profile: &str,
    package: &SkillPackage,
    findings: &[SkillFinding],
) -> ProfileCompatibilityResult {
    const FAIL_RULES: &[&str] = &["SKILL001", "SKILL002", "SKILL041"];
    const WARN_RULES: &[&str] = &["SKILL010", "SKILL020", "SKILL030", "SKILL040"];

    let finding_ids = compatibility_finding_ids_for_package(
        &package.manifest_path,
        findings,
        FAIL_RULES.iter().chain(WARN_RULES),
    );
    let has_fail = finding_ids
        .iter()
        .any(|rule_id| FAIL_RULES.contains(&rule_id.as_str()));
    let status = if has_fail {
        CompatibilityStatus::Fail
    } else if finding_ids.is_empty() {
        CompatibilityStatus::Pass
    } else {
        CompatibilityStatus::Warn
    };

    ProfileCompatibilityResult {
        profile: profile.to_owned(),
        status,
        finding_ids,
    }
}

fn compatibility_finding_ids_for_package<'a>(
    manifest_path: &str,
    findings: &[SkillFinding],
    rule_order: impl Iterator<Item = &'a &'a str>,
) -> Vec<String> {
    compatibility_finding_ids_for_package_matching(manifest_path, findings, rule_order, |_| true)
}

fn compatibility_finding_ids_for_package_matching<'a>(
    manifest_path: &str,
    findings: &[SkillFinding],
    rule_order: impl Iterator<Item = &'a &'a str>,
    include_finding: impl Fn(&SkillFinding) -> bool,
) -> Vec<String> {
    rule_order
        .filter(|rule_id| {
            findings.iter().any(|finding| {
                finding.rule_id == **rule_id
                    && finding.location.path == manifest_path
                    && include_finding(finding)
            })
        })
        .map(|rule_id| (*rule_id).to_owned())
        .collect()
}

fn evaluate_compatibility_findings(
    packages: &[SkillPackage],
    config: Option<&AuditConfig>,
) -> Vec<SkillFinding> {
    let profiles = selected_profiles(config);
    let include_claude = profiles.iter().any(|profile| profile == "claude-code");
    let include_codex = profiles.iter().any(|profile| profile == "codex");
    let include_github_copilot = profiles.iter().any(|profile| profile == "github-copilot");

    let mut findings = Vec::new();
    if include_claude {
        findings.extend(
            packages
                .iter()
                .filter(|package| is_claude_preferred_manifest_path(&package.manifest_path))
                .flat_map(claude_code_metadata_findings),
        );
    }
    if include_codex {
        findings.extend(
            packages
                .iter()
                .filter(|package| is_codex_preferred_manifest_path(&package.manifest_path))
                .flat_map(codex_metadata_findings),
        );
    }
    if include_github_copilot {
        findings.extend(
            packages
                .iter()
                .filter(|package| is_github_copilot_preferred_manifest_path(&package.manifest_path))
                .flat_map(github_copilot_metadata_findings),
        );
    }

    findings
}

fn claude_code_metadata_findings(package: &SkillPackage) -> Vec<SkillFinding> {
    const IGNORED_FIELDS: &[&str] = &["permissions", "tools"];

    package
        .manifest
        .frontmatter
        .keys()
        .filter(|field| IGNORED_FIELDS.contains(&field.as_str()))
        .map(|field| {
            compatibility_finding(
                "SKILL050",
                format!(
                    "Claude Code is likely to ignore the `{field}` frontmatter field; use `allowed-tools` for Claude tool allowlists or move advisory metadata into the Markdown body."
                ),
                package.manifest_path.clone(),
                Some(1),
            )
        })
        .collect()
}

fn codex_metadata_findings(package: &SkillPackage) -> Vec<SkillFinding> {
    let ignored_fields = profile_by_id("codex")
        .expect("codex profile definition must exist")
        .known_ignored_fields;

    package
        .manifest
        .frontmatter
        .keys()
        .filter(|field| {
            ignored_fields
                .iter()
                .any(|ignored_field| ignored_field.name == field.as_str())
        })
        .map(|field| {
            compatibility_finding(
                "SKILL050",
                format!(
                    "Codex is likely to ignore the `{field}` frontmatter field; document Codex tool or permission expectations with portable `tools` metadata or in the Markdown body."
                ),
                package.manifest_path.clone(),
                Some(1),
            )
        })
        .collect()
}

fn github_copilot_metadata_findings(package: &SkillPackage) -> Vec<SkillFinding> {
    let ignored_fields = profile_by_id("github-copilot")
        .expect("github-copilot profile definition must exist")
        .known_ignored_fields;

    package
        .manifest
        .frontmatter
        .keys()
        .filter(|field| {
            ignored_fields
                .iter()
                .any(|ignored_field| ignored_field.name == field.as_str())
        })
        .map(|field| {
            compatibility_finding(
                "SKILL050",
                format!(
                    "GitHub Copilot is likely to ignore the `{field}` frontmatter field; document GitHub Copilot tool expectations with portable `tools` metadata or in the Markdown body."
                ),
                package.manifest_path.clone(),
                Some(1),
            )
        })
        .collect()
}

fn compatibility_finding(
    rule_id: &str,
    message: String,
    path: String,
    line: Option<usize>,
) -> SkillFinding {
    let metadata = active_rule_metadata(rule_id)
        .expect("compatibility finding must have active registry metadata");

    SkillFinding {
        rule_id: metadata.id.as_str().to_owned(),
        severity: severity_from_metadata(metadata.severity),
        category: category_from_metadata(metadata.category),
        title: metadata.title.to_owned(),
        message,
        location: crate::model::FindingLocation { path, line },
        rationale: metadata.rationale.to_owned(),
        remediation: metadata.remediation.to_owned(),
        suppression: metadata.suppression_guidance.to_owned(),
    }
}

fn sort_skill_findings(findings: &mut [SkillFinding]) {
    findings.sort_by(|left, right| {
        left.location
            .path
            .cmp(&right.location.path)
            .then(left.location.line.cmp(&right.location.line))
            .then(left.rule_id.cmp(&right.rule_id))
            .then(left.message.cmp(&right.message))
    });
}

fn has_claude_unknown_frontmatter_field(package: &SkillPackage) -> bool {
    const ACCEPTED_FIELDS: &[&str] = &["allowed-tools", "description", "name"];
    const KNOWN_IGNORED_FIELDS: &[&str] = &["permissions", "tools"];

    package.manifest.frontmatter.keys().any(|field| {
        !ACCEPTED_FIELDS.contains(&field.as_str())
            && !KNOWN_IGNORED_FIELDS.contains(&field.as_str())
    })
}

fn has_codex_unknown_frontmatter_field(package: &SkillPackage) -> bool {
    let codex = profile_by_id("codex").expect("codex profile definition must exist");

    package.manifest.frontmatter.keys().any(|field| {
        !codex
            .required_fields
            .iter()
            .chain(codex.accepted_optional_fields)
            .chain(codex.known_ignored_fields)
            .any(|known_field| known_field.name == field.as_str())
            && field != "permissions"
    })
}

fn has_github_copilot_unknown_frontmatter_field(package: &SkillPackage) -> bool {
    let github_copilot =
        profile_by_id("github-copilot").expect("github-copilot profile definition must exist");

    package.manifest.frontmatter.keys().any(|field| {
        !github_copilot
            .required_fields
            .iter()
            .chain(github_copilot.accepted_optional_fields)
            .chain(github_copilot.known_ignored_fields)
            .any(|known_field| known_field.name == field.as_str())
    })
}

fn is_profile_accepted_frontmatter_field(profiles: &[String], field: &str) -> bool {
    is_claude_accepted_frontmatter_field(profiles, field)
}

fn is_claude_accepted_frontmatter_field(profiles: &[String], field: &str) -> bool {
    field == "allowed-tools" && profiles.iter().any(|profile| profile == "claude-code")
}

fn is_claude_preferred_manifest_path(path: &str) -> bool {
    let path = normalize_report_path(path);
    let Some(skill_path) = path.strip_prefix(".claude/skills/") else {
        return false;
    };
    let Some(skill_name) = skill_path.strip_suffix("/SKILL.md") else {
        return false;
    };

    !skill_name.is_empty() && !skill_name.contains('/')
}

fn is_codex_preferred_manifest_path(path: &str) -> bool {
    let path = normalize_report_path(path);
    let Some(skill_path) = path.strip_prefix(".agents/skills/") else {
        return false;
    };
    let Some(skill_name) = skill_path.strip_suffix("/SKILL.md") else {
        return false;
    };

    !skill_name.is_empty() && !skill_name.contains('/')
}

fn is_github_copilot_preferred_manifest_path(path: &str) -> bool {
    let path = normalize_report_path(path);
    let Some(skill_path) = path.strip_prefix(".github/skills/") else {
        return false;
    };
    let Some(skill_name) = skill_path.strip_suffix("/SKILL.md") else {
        return false;
    };

    !skill_name.is_empty() && !skill_name.contains('/')
}

fn has_codex_permission_metadata(package: &SkillPackage) -> bool {
    package.manifest.frontmatter.contains_key("permissions")
}

fn has_github_copilot_unsupported_global_metadata(package: &SkillPackage) -> bool {
    package.manifest.frontmatter.contains_key("permissions")
}

fn has_script_reference_or_artifact(package: &SkillPackage) -> bool {
    package
        .graph
        .references
        .iter()
        .any(|reference| normalize_report_path(&reference.target).starts_with("scripts/"))
        || package
            .graph
            .files
            .iter()
            .any(|file| file.artifact == SkillArtifactKind::Scripts)
        || package
            .graph
            .artifacts
            .iter()
            .any(|artifact| artifact == "scripts")
}

fn selected_profiles(config: Option<&AuditConfig>) -> Vec<String> {
    match config {
        Some(config) if !config.profiles.is_empty() => config.profiles.clone(),
        _ => HOST_PROFILES
            .iter()
            .map(|profile| (*profile).to_owned())
            .collect(),
    }
}

fn skill_finding_from_evaluated_rule(finding: EvaluatedRuleFinding) -> SkillFinding {
    let metadata = active_rule_metadata(finding.rule_id.as_str())
        .expect("evaluated structural rule must have active registry metadata");

    SkillFinding {
        rule_id: metadata.id.as_str().to_owned(),
        severity: severity_from_metadata(metadata.severity),
        category: category_from_metadata(metadata.category),
        title: metadata.title.to_owned(),
        message: finding.message,
        location: crate::model::FindingLocation {
            path: finding.location.path,
            line: finding.location.line,
        },
        rationale: metadata.rationale.to_owned(),
        remediation: metadata.remediation.to_owned(),
        suppression: metadata.suppression_guidance.to_owned(),
    }
}

fn severity_from_metadata(severity: RegistrySeverity) -> crate::model::Severity {
    match severity {
        RegistrySeverity::Info => crate::model::Severity::Info,
        RegistrySeverity::Low => crate::model::Severity::Low,
        RegistrySeverity::Medium => crate::model::Severity::Medium,
        RegistrySeverity::High => crate::model::Severity::High,
        RegistrySeverity::Critical => crate::model::Severity::Critical,
    }
}

fn category_from_metadata(category: RegistryCategory) -> crate::model::FindingCategory {
    match category {
        RegistryCategory::Spec => crate::model::FindingCategory::Spec,
        RegistryCategory::Compatibility => crate::model::FindingCategory::Compatibility,
        RegistryCategory::Security => crate::model::FindingCategory::Security,
        RegistryCategory::Quality => crate::model::FindingCategory::Quality,
        RegistryCategory::Portability => crate::model::FindingCategory::Portability,
        RegistryCategory::Reproducibility => crate::model::FindingCategory::Reproducibility,
    }
}

fn apply_suppressions(
    findings: Vec<SkillFinding>,
    config: Option<&AuditConfig>,
) -> (Vec<SkillFinding>, Vec<SuppressedFinding>) {
    let Some(config) = config else {
        return (findings, Vec::new());
    };

    let mut unsuppressed = Vec::new();
    let mut suppressed = Vec::new();

    for finding in findings {
        match matching_ignore_entry(&finding, &config.ignore) {
            Some(entry) => suppressed.push(SuppressedFinding {
                finding,
                suppression: SuppressionMatch {
                    matched_rule: entry.rule.clone(),
                    matched_path: entry.path.clone(),
                    reason: entry.reason.clone(),
                },
            }),
            None => unsuppressed.push(finding),
        }
    }

    (unsuppressed, suppressed)
}

fn matching_ignore_entry<'a>(
    finding: &SkillFinding,
    entries: &'a [ConfigIgnoreEntry],
) -> Option<&'a ConfigIgnoreEntry> {
    let finding_path = normalize_report_path(&finding.location.path);

    entries
        .iter()
        .find(|entry| entry.rule == finding.rule_id && entry.path == finding_path)
}

fn normalize_report_path(path: &str) -> String {
    path.replace('\\', "/")
}

fn resolve_references(skill_root: &Path, references: &[SkillReference]) -> Vec<SkillReference> {
    references
        .iter()
        .filter_map(|reference| resolve_reference(skill_root, reference))
        .collect()
}

fn resolve_reference(skill_root: &Path, reference: &SkillReference) -> Option<SkillReference> {
    let mut resolved = reference.clone();
    match relative_probe_target(&reference.target)? {
        RelativeProbeTarget::Safe(target) => {
            resolved.exists = Some(path_exists_without_symlink_dirs(skill_root, target));
        }
        RelativeProbeTarget::Unsafe => {
            resolved.exists = Some(false);
        }
    }
    Some(resolved)
}

enum RelativeProbeTarget<'a> {
    Safe(&'a str),
    Unsafe,
}

fn relative_probe_target(target: &str) -> Option<RelativeProbeTarget<'_>> {
    let target = strip_query_and_fragment(target);

    if target.is_empty() {
        return None;
    }
    if has_windows_prefix(target) || is_absolute_path_target(target) || has_parent_component(target)
    {
        return Some(RelativeProbeTarget::Unsafe);
    }
    if has_uri_scheme(target) {
        return None;
    }

    Some(RelativeProbeTarget::Safe(target))
}

fn strip_query_and_fragment(target: &str) -> &str {
    match (target.find('?'), target.find('#')) {
        (Some(query), Some(fragment)) => &target[..query.min(fragment)],
        (Some(index), None) | (None, Some(index)) => &target[..index],
        (None, None) => target,
    }
}

fn has_uri_scheme(target: &str) -> bool {
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

fn has_windows_prefix(target: &str) -> bool {
    let bytes = target.as_bytes();
    matches!(
        bytes,
        [drive, b':', ..] if drive.is_ascii_alphabetic()
    ) || target.starts_with(r"\\")
        || target.starts_with("//")
}

fn is_absolute_path_target(target: &str) -> bool {
    target.starts_with('/') || target.starts_with('\\') || Path::new(target).is_absolute()
}

fn has_parent_component(target: &str) -> bool {
    target.split(['/', '\\']).any(|component| component == "..")
}

fn path_exists_without_symlink_dirs(skill_root: &Path, target: &str) -> bool {
    let components = target
        .split(['/', '\\'])
        .filter(|component| !component.is_empty() && *component != ".")
        .collect::<Vec<_>>();

    if components.is_empty() {
        return false;
    }

    let mut current = skill_root.to_path_buf();
    for (index, component) in components.iter().enumerate() {
        current.push(component);
        let Ok(metadata) = std::fs::symlink_metadata(&current) else {
            return false;
        };
        let is_final = index + 1 == components.len();
        if metadata.file_type().is_symlink() {
            return is_final;
        }
        if !is_final && !metadata.is_dir() {
            return false;
        }
    }

    true
}

fn discover_artifacts(skill_root: &Path) -> Vec<String> {
    ["scripts", "references", "assets"]
        .iter()
        .map(|name| skill_root.join(name))
        .filter(|path| {
            std::fs::symlink_metadata(path)
                .map(|metadata| metadata.file_type().is_dir())
                .unwrap_or(false)
        })
        .map(|path| display_path(skill_root, &path))
        .collect()
}

fn inventory_artifact_files(skill_root: &Path) -> AuditResult<Vec<SkillFile>> {
    let mut files = Vec::new();

    for (name, artifact) in [
        ("scripts", SkillArtifactKind::Scripts),
        ("references", SkillArtifactKind::References),
        ("assets", SkillArtifactKind::Assets),
    ] {
        let artifact_root = skill_root.join(name);
        let metadata =
            match std::fs::symlink_metadata(&artifact_root).map_err(|source| AuditError::Metadata {
                path: artifact_root.clone(),
                source,
            }) {
                Ok(metadata) => metadata,
                Err(AuditError::Metadata { source, .. })
                    if source.kind() == std::io::ErrorKind::NotFound =>
                {
                    continue;
                }
                Err(error) => return Err(error),
            };

        if metadata.is_dir() {
            inventory_directory(skill_root, &artifact_root, artifact, &mut files)?;
        }
    }

    files.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then(left.artifact.cmp(&right.artifact))
            .then(left.kind.cmp(&right.kind))
    });
    Ok(files)
}

fn inventory_directory(
    skill_root: &Path,
    directory: &Path,
    artifact: SkillArtifactKind,
    files: &mut Vec<SkillFile>,
) -> AuditResult<()> {
    let mut entries = std::fs::read_dir(directory)
        .map_err(|source| AuditError::ReadDir {
            path: directory.to_path_buf(),
            source,
        })?
        .map(|entry| {
            entry.map_err(|source| AuditError::ReadDir {
                path: directory.to_path_buf(),
                source,
            })
        })
        .collect::<AuditResult<Vec<_>>>()?;

    entries.sort_by(|left, right| left.path().cmp(&right.path()));

    for entry in entries {
        let path = entry.path();
        let metadata = std::fs::symlink_metadata(&path).map_err(|source| AuditError::Metadata {
            path: path.clone(),
            source,
        })?;
        let kind = file_kind(&metadata);
        files.push(SkillFile {
            path: display_path(skill_root, &path),
            artifact,
            kind,
            size_bytes: if kind == SkillFileKind::Directory {
                0
            } else {
                metadata.len()
            },
            readonly: metadata.permissions().readonly(),
        });

        if kind == SkillFileKind::Directory {
            inventory_directory(skill_root, &path, artifact, files)?;
        }
    }

    Ok(())
}

fn file_kind(metadata: &std::fs::Metadata) -> SkillFileKind {
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        SkillFileKind::Symlink
    } else if file_type.is_file() {
        SkillFileKind::File
    } else if file_type.is_dir() {
        SkillFileKind::Directory
    } else {
        SkillFileKind::Other
    }
}

fn display_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn frontmatter_key_lines(content: &str) -> BTreeMap<String, usize> {
    let Some(frontmatter) = frontmatter_content(content) else {
        return BTreeMap::new();
    };

    frontmatter
        .lines()
        .enumerate()
        .filter_map(|(index, line)| top_level_frontmatter_key(line).map(|key| (key, index + 2)))
        .collect()
}

fn frontmatter_content(content: &str) -> Option<&str> {
    let content_after_bom = content.strip_prefix(UTF8_BOM).unwrap_or(content);
    let delimiter_offset = content.len() - content_after_bom.len();
    let after_opening_delimiter = content_after_bom.strip_prefix("---")?;
    let opening_line_ending_len = line_ending_len(after_opening_delimiter)?;
    let frontmatter_start = delimiter_offset + "---".len() + opening_line_ending_len;
    let mut line_start = frontmatter_start;

    while line_start <= content.len() {
        let line_end = content[line_start..]
            .find('\n')
            .map_or(content.len(), |offset| line_start + offset + 1);
        let line = &content[line_start..line_end];
        if trim_line_ending(line) == "---" {
            return Some(&content[frontmatter_start..line_start]);
        }
        if line_end == content.len() {
            break;
        }
        line_start = line_end;
    }

    None
}

fn line_ending_len(value: &str) -> Option<usize> {
    if value.starts_with("\r\n") {
        Some(2)
    } else if value.starts_with('\n') {
        Some(1)
    } else {
        None
    }
}

fn trim_line_ending(line: &str) -> &str {
    line.strip_suffix("\r\n")
        .or_else(|| line.strip_suffix('\n'))
        .unwrap_or(line)
}

fn top_level_frontmatter_key(line: &str) -> Option<String> {
    if line.is_empty()
        || line.starts_with(char::is_whitespace)
        || line.starts_with('#')
        || line.starts_with('-')
    {
        return None;
    }

    let (key, _value) = line.split_once(':')?;
    let key = key.trim().trim_matches(['"', '\'']);
    (!key.is_empty()).then(|| key.to_owned())
}

fn empty_skill_manifest() -> SkillManifest {
    SkillManifest {
        name: None,
        description: None,
        frontmatter: BTreeMap::new(),
        body: String::new(),
        headings: Vec::new(),
        links: Vec::new(),
        inline_code: Vec::new(),
        code_blocks: Vec::new(),
        declared_tools: Vec::new(),
        declared_permissions: Vec::new(),
    }
}

fn empty_skill_graph() -> SkillGraph {
    SkillGraph {
        references: Vec::new(),
        artifacts: Vec::new(),
        files: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse_audit_config;
    use crate::model::{FindingCategory, Severity, SkillFinding};
    use crate::test_support::TestWorkspace;
    use agent_audit_hosts::{CompatibilityStatus, HOST_PROFILES};
    use agent_audit_rules::{
        rule_metadata, RuleCategory as RegistryCategory, RuleSeverity as RegistrySeverity,
    };
    use std::io::ErrorKind;

    #[test]
    fn scan_reports_valid_manifest_with_references_and_artifacts() {
        let workspace = TestWorkspace::new("scan-valid");
        workspace.write_file(
            "SKILL.md",
            r#"---
name: valid-skill
description: Valid skill fixture.
---

# Valid Skill

Read [local guidance](references/guidance.md), [remote guidance](https://example.test),
and [heading](#valid-skill).
"#,
        );
        workspace.write_file("references/guidance.md", "# Guidance\n");
        workspace.create_dir("scripts");
        workspace.create_dir("assets");

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");

        assert_eq!(report.summary.package_count, 1);
        assert_eq!(report.summary.finding_count, 0);
        assert_eq!(report.summary.invalid_manifest_count, 0);
        assert_eq!(report.summary.broken_reference_count, 0);
        assert_eq!(report.packages[0].root, "");
        assert_eq!(report.packages[0].manifest_path, "SKILL.md");
        assert_eq!(
            report.packages[0]
                .graph
                .references
                .iter()
                .map(|reference| (&reference.target, reference.exists))
                .collect::<Vec<_>>(),
            vec![(&"references/guidance.md".to_owned(), Some(true))]
        );
        assert_eq!(
            report.packages[0].graph.artifacts,
            vec!["scripts", "references", "assets"]
        );
        assert_eq!(report.packages[0].graph.files.len(), 1);
        assert_eq!(
            report.packages[0].graph.files[0].path,
            "references/guidance.md"
        );
        assert_eq!(
            report.packages[0].graph.files[0].artifact,
            SkillArtifactKind::References
        );
        assert_eq!(report.packages[0].graph.files[0].kind, SkillFileKind::File);
        assert_eq!(report.packages[0].graph.files[0].size_bytes, 11);
    }

    #[test]
    fn scan_default_compatibility_matrix_uses_all_profiles_in_registry_order() {
        let workspace = TestWorkspace::new("scan-default-compatibility");
        workspace.write_file(
            "SKILL.md",
            r#"---
name: default-compatibility
description: Default compatibility fixture.
---

# Default Compatibility
"#,
        );

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");

        assert_eq!(report.compatibility.profiles, string_vec(HOST_PROFILES));
        assert_eq!(report.compatibility.matrix.len(), 1);
        assert_eq!(report.compatibility.matrix[0].path, "SKILL.md");
        assert_eq!(
            report.compatibility.matrix[0].name.as_deref(),
            Some("default-compatibility")
        );
        assert_eq!(
            compatibility_projection(&report.compatibility.matrix[0].profiles),
            vec![
                (
                    "agent-skills-spec",
                    CompatibilityStatus::Pass,
                    Vec::<&str>::new()
                ),
                ("claude-code", CompatibilityStatus::Warn, Vec::<&str>::new()),
                ("codex", CompatibilityStatus::Warn, Vec::<&str>::new()),
                (
                    "github-copilot",
                    CompatibilityStatus::Warn,
                    Vec::<&str>::new()
                ),
                (
                    "vscode-copilot",
                    CompatibilityStatus::Unknown,
                    Vec::<&str>::new()
                ),
                ("generic", CompatibilityStatus::Pass, Vec::<&str>::new()),
            ]
        );
        assert_eq!(report.summary.finding_count, 0);
        assert_eq!(report.summary.suppressed_finding_count, 0);
    }

    #[test]
    fn scan_default_profiles_emit_claude_ignored_metadata_skill050() {
        let workspace = TestWorkspace::new("scan-default-claude-ignored-metadata");
        workspace.write_file(
            ".claude/skills/reviewer/SKILL.md",
            r#"---
name: reviewer
description: Reviews code changes.
tools:
  - shell
---

# Reviewer
"#,
        );

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");

        assert_eq!(
            report
                .findings
                .iter()
                .map(|finding| finding.rule_id.as_str())
                .collect::<Vec<_>>(),
            vec!["SKILL050"]
        );
        assert_eq!(
            ".claude/skills/reviewer/SKILL.md",
            report.findings[0].location.path
        );
        assert!(report.findings[0].message.contains("`tools`"));
        assert_eq!(
            compatibility_projection(&report.compatibility.matrix[0].profiles),
            vec![
                (
                    "agent-skills-spec",
                    CompatibilityStatus::Pass,
                    Vec::<&str>::new()
                ),
                ("claude-code", CompatibilityStatus::Warn, vec!["SKILL050"]),
                ("codex", CompatibilityStatus::Warn, Vec::<&str>::new()),
                (
                    "github-copilot",
                    CompatibilityStatus::Warn,
                    Vec::<&str>::new()
                ),
                (
                    "vscode-copilot",
                    CompatibilityStatus::Unknown,
                    Vec::<&str>::new()
                ),
                ("generic", CompatibilityStatus::Pass, Vec::<&str>::new()),
            ]
        );
    }

    #[test]
    fn scan_agent_skills_spec_warns_for_unsuppressed_baseline_warnings() {
        let workspace = TestWorkspace::new("scan-agent-spec-warn");
        workspace.write_file(
            "SKILL.md",
            r#"---
name: baseline-warn
description: Baseline warning fixture.
owner: platform
---

# Baseline Warning

Read [missing](references/missing.md).
"#,
        );

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");

        assert_eq!(
            report
                .findings
                .iter()
                .map(|finding| finding.rule_id.as_str())
                .collect::<Vec<_>>(),
            vec!["SKILL040", "SKILL010"]
        );
        assert_eq!(
            compatibility_projection(&report.compatibility.matrix[0].profiles),
            vec![
                (
                    "agent-skills-spec",
                    CompatibilityStatus::Warn,
                    vec!["SKILL010", "SKILL040"]
                ),
                (
                    "claude-code",
                    CompatibilityStatus::Warn,
                    vec!["SKILL010", "SKILL040"]
                ),
                (
                    "codex",
                    CompatibilityStatus::Warn,
                    vec!["SKILL010", "SKILL040"]
                ),
                (
                    "github-copilot",
                    CompatibilityStatus::Warn,
                    vec!["SKILL010", "SKILL040"]
                ),
                (
                    "vscode-copilot",
                    CompatibilityStatus::Unknown,
                    Vec::<&str>::new()
                ),
                (
                    "generic",
                    CompatibilityStatus::Warn,
                    vec!["SKILL010", "SKILL040"]
                ),
            ]
        );
    }

    #[test]
    fn scan_agent_skills_spec_fails_for_required_baseline_findings() {
        let workspace = TestWorkspace::new("scan-agent-spec-fail");
        workspace.write_file(
            "SKILL.md",
            r#"---
description: Missing name fixture.
owner: platform
---

This manifest intentionally has no heading fallback.
"#,
        );

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");

        assert_eq!(
            report
                .findings
                .iter()
                .map(|finding| finding.rule_id.as_str())
                .collect::<Vec<_>>(),
            vec!["SKILL001", "SKILL040"]
        );
        assert_eq!(
            compatibility_projection(&report.compatibility.matrix[0].profiles)[0],
            (
                "agent-skills-spec",
                CompatibilityStatus::Fail,
                vec!["SKILL001", "SKILL040"]
            )
        );
    }

    #[test]
    fn scan_claude_code_preferred_path_passes() {
        let workspace = TestWorkspace::new("scan-claude-preferred-pass");
        workspace.write_file(
            ".claude/skills/reviewer/SKILL.md",
            r#"---
name: reviewer
description: Reviews code changes.
---

# Reviewer
"#,
        );
        let config = parse_audit_config(
            r#"
profiles:
  - claude-code
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert!(report.findings.is_empty());
        assert_eq!(
            compatibility_projection(&report.compatibility.matrix[0].profiles),
            vec![("claude-code", CompatibilityStatus::Pass, Vec::<&str>::new())]
        );
    }

    #[test]
    fn scan_claude_code_allowed_tools_does_not_report_skill040() {
        let workspace = TestWorkspace::new("scan-claude-allowed-tools-pass");
        workspace.write_file(
            ".claude/skills/reviewer/SKILL.md",
            r#"---
name: reviewer
description: Reviews code changes.
allowed-tools:
  - Bash(git diff:*)
---

# Reviewer
"#,
        );
        let config = parse_audit_config(
            r#"
profiles:
  - claude-code
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert!(report.findings.is_empty());
        assert_eq!(
            compatibility_projection(&report.compatibility.matrix[0].profiles),
            vec![("claude-code", CompatibilityStatus::Pass, Vec::<&str>::new())]
        );
    }

    #[test]
    fn scan_claude_code_allowed_tools_on_root_skill_warns_only_for_path() {
        let workspace = TestWorkspace::new("scan-claude-root-allowed-tools-path-warn");
        workspace.write_file(
            "SKILL.md",
            r#"---
name: reviewer
description: Reviews code changes.
allowed-tools:
  - Bash(git diff:*)
---

# Reviewer
"#,
        );
        let config = parse_audit_config(
            r#"
profiles:
  - claude-code
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert!(report.findings.is_empty());
        assert_eq!(
            compatibility_projection(&report.compatibility.matrix[0].profiles),
            vec![("claude-code", CompatibilityStatus::Warn, Vec::<&str>::new())]
        );
    }

    #[test]
    fn scan_claude_code_warns_for_non_claude_path_without_finding_id() {
        let workspace = TestWorkspace::new("scan-claude-path-warn");
        workspace.write_file(
            "SKILL.md",
            r#"---
name: reviewer
description: Reviews code changes.
---

# Reviewer
"#,
        );
        let config = parse_audit_config(
            r#"
profiles:
  - claude-code
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert!(report.findings.is_empty());
        assert_eq!(
            compatibility_projection(&report.compatibility.matrix[0].profiles),
            vec![("claude-code", CompatibilityStatus::Warn, Vec::<&str>::new())]
        );
    }

    #[test]
    fn scan_claude_code_warns_for_ignored_metadata_with_skill050() {
        let workspace = TestWorkspace::new("scan-claude-ignored-metadata");
        workspace.write_file(
            ".claude/skills/reviewer/SKILL.md",
            r#"---
name: reviewer
description: Reviews code changes.
tools:
  - shell
---

# Reviewer
"#,
        );
        let config = parse_audit_config(
            r#"
profiles:
  - claude-code
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].rule_id, "SKILL050");
        assert_eq!(report.findings[0].category, FindingCategory::Compatibility);
        assert_eq!(
            report.findings[0].location.path,
            ".claude/skills/reviewer/SKILL.md"
        );
        assert!(report.findings[0].message.contains("`tools`"));
        assert_eq!(
            compatibility_projection(&report.compatibility.matrix[0].profiles),
            vec![("claude-code", CompatibilityStatus::Warn, vec!["SKILL050"])]
        );
    }

    #[test]
    fn scan_claude_code_warns_for_script_references_without_finding_id() {
        let workspace = TestWorkspace::new("scan-claude-script-warn");
        workspace.write_file(
            ".claude/skills/reviewer/SKILL.md",
            r#"---
name: reviewer
description: Reviews code changes.
---

# Reviewer

Run [check](scripts/check.sh) when explicitly requested.
"#,
        );
        workspace.write_file(".claude/skills/reviewer/scripts/check.sh", "echo check\n");
        let config = parse_audit_config(
            r#"
profiles:
  - claude-code
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert!(report.findings.is_empty());
        assert_eq!(
            compatibility_projection(&report.compatibility.matrix[0].profiles),
            vec![("claude-code", CompatibilityStatus::Warn, Vec::<&str>::new())]
        );
    }

    #[test]
    fn scan_claude_code_fails_for_baseline_required_findings() {
        let workspace = TestWorkspace::new("scan-claude-baseline-fail");
        workspace.write_file(
            ".claude/skills/reviewer/SKILL.md",
            r#"---
name: reviewer
---
"#,
        );
        let config = parse_audit_config(
            r#"
profiles:
  - claude-code
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert_eq!(
            compatibility_projection(&report.compatibility.matrix[0].profiles),
            vec![("claude-code", CompatibilityStatus::Fail, vec!["SKILL002"])]
        );
    }

    #[test]
    fn scan_claude_code_ignores_suppressed_skill050() {
        let workspace = TestWorkspace::new("scan-claude-suppressed-skill050");
        workspace.write_file(
            ".claude/skills/reviewer/SKILL.md",
            r#"---
name: reviewer
description: Reviews code changes.
tools:
  - shell
---
"#,
        );
        let config = parse_audit_config(
            r#"
profiles:
  - claude-code

ignore:
  - rule: SKILL050
    path: .claude/skills/reviewer/SKILL.md
    reason: Claude wrapper translates portable tools metadata.
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert!(report.findings.is_empty());
        assert_eq!(report.summary.suppressed_finding_count, 1);
        assert_eq!(
            compatibility_projection(&report.compatibility.matrix[0].profiles),
            vec![("claude-code", CompatibilityStatus::Pass, Vec::<&str>::new())]
        );
    }

    #[test]
    fn scan_explicit_config_profiles_preserves_claude_order() {
        let workspace = TestWorkspace::new("scan-claude-profile-order");
        workspace.write_file(
            ".claude/skills/reviewer/SKILL.md",
            r#"---
name: reviewer
description: Reviews code changes.
---
"#,
        );
        let config = parse_audit_config(
            r#"
profiles:
  - generic
  - claude-code
  - agent-skills-spec
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert_eq!(
            report.compatibility.profiles,
            vec!["generic", "claude-code", "agent-skills-spec"]
        );
        assert_eq!(
            compatibility_projection(&report.compatibility.matrix[0].profiles),
            vec![
                ("generic", CompatibilityStatus::Pass, Vec::<&str>::new()),
                ("claude-code", CompatibilityStatus::Pass, Vec::<&str>::new()),
                (
                    "agent-skills-spec",
                    CompatibilityStatus::Pass,
                    Vec::<&str>::new()
                ),
            ]
        );
    }

    #[test]
    fn scan_codex_preferred_path_with_tools_passes() {
        let workspace = TestWorkspace::new("scan-codex-preferred-pass");
        workspace.write_file(
            ".agents/skills/reviewer/SKILL.md",
            r#"---
name: reviewer
description: Reviews code changes.
tools:
  - shell
---

# Reviewer
"#,
        );
        let config = parse_audit_config(
            r#"
profiles:
  - codex
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert!(report.findings.is_empty());
        assert_eq!(
            compatibility_projection(&report.compatibility.matrix[0].profiles),
            vec![("codex", CompatibilityStatus::Pass, Vec::<&str>::new())]
        );
    }

    #[test]
    fn scan_codex_warns_for_non_codex_path_without_finding_id() {
        let workspace = TestWorkspace::new("scan-codex-path-warn");
        workspace.write_file(
            "SKILL.md",
            r#"---
name: reviewer
description: Reviews code changes.
---

# Reviewer
"#,
        );
        let config = parse_audit_config(
            r#"
profiles:
  - codex
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert!(report.findings.is_empty());
        assert_eq!(
            compatibility_projection(&report.compatibility.matrix[0].profiles),
            vec![("codex", CompatibilityStatus::Warn, Vec::<&str>::new())]
        );
    }

    #[test]
    fn scan_codex_warns_for_ignored_allowed_tools_with_skill050() {
        let workspace = TestWorkspace::new("scan-codex-ignored-allowed-tools");
        workspace.write_file(
            ".agents/skills/reviewer/SKILL.md",
            r#"---
name: reviewer
description: Reviews code changes.
allowed-tools:
  - Bash(git diff:*)
---

# Reviewer
"#,
        );
        let config = parse_audit_config(
            r#"
profiles:
  - codex
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        let mut rule_ids = report
            .findings
            .iter()
            .map(|finding| finding.rule_id.as_str())
            .collect::<Vec<_>>();
        rule_ids.sort_unstable();
        assert_eq!(rule_ids, vec!["SKILL040", "SKILL050"]);
        let codex_finding = report
            .findings
            .iter()
            .find(|finding| finding.rule_id == "SKILL050")
            .expect("Codex compatibility finding");
        assert_eq!(codex_finding.category, FindingCategory::Compatibility);
        assert_eq!(
            codex_finding.location.path,
            ".agents/skills/reviewer/SKILL.md"
        );
        assert!(codex_finding.message.contains("`allowed-tools`"));
        assert_eq!(
            compatibility_projection(&report.compatibility.matrix[0].profiles),
            vec![("codex", CompatibilityStatus::Warn, vec!["SKILL050"])]
        );
    }

    #[test]
    fn scan_combined_spec_and_codex_keeps_structural_allowed_tools_finding() {
        let workspace = TestWorkspace::new("scan-codex-combined-allowed-tools");
        workspace.write_file(
            ".agents/skills/reviewer/SKILL.md",
            r#"---
name: reviewer
description: Reviews code changes.
allowed-tools:
  - Bash(git diff:*)
---

# Reviewer
"#,
        );
        let config = parse_audit_config(
            r#"
profiles:
  - agent-skills-spec
  - codex
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        let mut rule_ids = report
            .findings
            .iter()
            .map(|finding| finding.rule_id.as_str())
            .collect::<Vec<_>>();
        rule_ids.sort_unstable();
        assert_eq!(rule_ids, vec!["SKILL040", "SKILL050"]);
        assert!(report
            .findings
            .iter()
            .all(|finding| finding.message.contains("`allowed-tools`")));
        assert_eq!(
            compatibility_projection(&report.compatibility.matrix[0].profiles),
            vec![
                (
                    "agent-skills-spec",
                    CompatibilityStatus::Warn,
                    vec!["SKILL040"]
                ),
                ("codex", CompatibilityStatus::Warn, vec!["SKILL050"]),
            ]
        );
    }

    #[test]
    fn scan_codex_warns_for_permissions_without_finding_id() {
        let workspace = TestWorkspace::new("scan-codex-permissions-warn");
        workspace.write_file(
            ".agents/skills/reviewer/SKILL.md",
            r#"---
name: reviewer
description: Reviews code changes.
permissions:
  - filesystem-read
---

# Reviewer
"#,
        );
        let config = parse_audit_config(
            r#"
profiles:
  - codex
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert!(report.findings.is_empty());
        assert_eq!(
            compatibility_projection(&report.compatibility.matrix[0].profiles),
            vec![("codex", CompatibilityStatus::Warn, Vec::<&str>::new())]
        );
    }

    #[test]
    fn scan_codex_warns_for_script_references_without_finding_id() {
        let workspace = TestWorkspace::new("scan-codex-script-warn");
        workspace.write_file(
            ".agents/skills/reviewer/SKILL.md",
            r#"---
name: reviewer
description: Reviews code changes.
---

# Reviewer

Run [check](scripts/check.sh) when explicitly requested.
"#,
        );
        workspace.write_file(".agents/skills/reviewer/scripts/check.sh", "echo check\n");
        let config = parse_audit_config(
            r#"
profiles:
  - codex
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert!(report.findings.is_empty());
        assert_eq!(
            compatibility_projection(&report.compatibility.matrix[0].profiles),
            vec![("codex", CompatibilityStatus::Warn, Vec::<&str>::new())]
        );
    }

    #[test]
    fn scan_codex_fails_for_baseline_required_findings() {
        let workspace = TestWorkspace::new("scan-codex-baseline-fail");
        workspace.write_file(
            ".agents/skills/reviewer/SKILL.md",
            r#"---
name: reviewer
---
"#,
        );
        let config = parse_audit_config(
            r#"
profiles:
  - codex
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert_eq!(
            compatibility_projection(&report.compatibility.matrix[0].profiles),
            vec![("codex", CompatibilityStatus::Fail, vec!["SKILL002"])]
        );
    }

    #[test]
    fn scan_codex_ignores_suppressed_skill050() {
        let workspace = TestWorkspace::new("scan-codex-suppressed-skill050");
        workspace.write_file(
            ".agents/skills/reviewer/SKILL.md",
            r#"---
name: reviewer
description: Reviews code changes.
allowed-tools:
  - Bash(git diff:*)
---
"#,
        );
        let config = parse_audit_config(
            r#"
profiles:
  - codex

ignore:
  - rule: SKILL050
    path: .agents/skills/reviewer/SKILL.md
    reason: Codex wrapper translates Claude-style tool metadata.
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert_eq!(
            report
                .findings
                .iter()
                .map(|finding| finding.rule_id.as_str())
                .collect::<Vec<_>>(),
            vec!["SKILL040"]
        );
        assert_eq!(report.summary.suppressed_finding_count, 1);
        assert_eq!(
            compatibility_projection(&report.compatibility.matrix[0].profiles),
            vec![("codex", CompatibilityStatus::Pass, Vec::<&str>::new())]
        );
    }

    #[test]
    fn scan_github_copilot_preferred_path_with_tools_passes() {
        let workspace = TestWorkspace::new("scan-github-copilot-preferred-pass");
        workspace.write_file(
            ".github/skills/reviewer/SKILL.md",
            r#"---
name: reviewer
description: Reviews repository changes.
tools:
  - shell
---

# Reviewer
"#,
        );
        let config = parse_audit_config(
            r#"
profiles:
  - github-copilot
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert!(report.findings.is_empty());
        assert_eq!(
            compatibility_projection(&report.compatibility.matrix[0].profiles),
            vec![(
                "github-copilot",
                CompatibilityStatus::Pass,
                Vec::<&str>::new()
            )]
        );
    }

    #[test]
    fn scan_github_copilot_warns_for_permissions_without_finding_id() {
        let workspace = TestWorkspace::new("scan-github-copilot-permissions-warn");
        workspace.write_file(
            ".github/skills/reviewer/SKILL.md",
            r#"---
name: reviewer
description: Reviews repository changes.
permissions:
  network: false
---

# Reviewer
"#,
        );
        let config = parse_audit_config(
            r#"
profiles:
  - github-copilot
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert!(report.findings.is_empty());
        assert_eq!(
            compatibility_projection(&report.compatibility.matrix[0].profiles),
            vec![(
                "github-copilot",
                CompatibilityStatus::Warn,
                Vec::<&str>::new()
            )]
        );
    }

    #[test]
    fn scan_github_copilot_warns_for_non_github_path_without_finding_id() {
        let workspace = TestWorkspace::new("scan-github-copilot-path-warn");
        workspace.write_file(
            "SKILL.md",
            r#"---
name: reviewer
description: Reviews repository changes.
---

# Reviewer
"#,
        );
        let config = parse_audit_config(
            r#"
profiles:
  - github-copilot
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert!(report.findings.is_empty());
        assert_eq!(
            compatibility_projection(&report.compatibility.matrix[0].profiles),
            vec![(
                "github-copilot",
                CompatibilityStatus::Warn,
                Vec::<&str>::new()
            )]
        );
    }

    #[test]
    fn scan_github_copilot_warns_for_ignored_allowed_tools_with_skill050() {
        let workspace = TestWorkspace::new("scan-github-copilot-ignored-allowed-tools");
        workspace.write_file(
            ".github/skills/reviewer/SKILL.md",
            r#"---
name: reviewer
description: Reviews repository changes.
allowed-tools:
  - Bash(git diff:*)
---

# Reviewer
"#,
        );
        let config = parse_audit_config(
            r#"
profiles:
  - github-copilot
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        let mut rule_ids = report
            .findings
            .iter()
            .map(|finding| finding.rule_id.as_str())
            .collect::<Vec<_>>();
        rule_ids.sort_unstable();
        assert_eq!(rule_ids, vec!["SKILL040", "SKILL050"]);
        let github_copilot_finding = report
            .findings
            .iter()
            .find(|finding| finding.rule_id == "SKILL050")
            .expect("GitHub Copilot compatibility finding");
        assert_eq!(
            github_copilot_finding.category,
            FindingCategory::Compatibility
        );
        assert_eq!(
            github_copilot_finding.location.path,
            ".github/skills/reviewer/SKILL.md"
        );
        assert!(github_copilot_finding.message.contains("`allowed-tools`"));
        assert_eq!(
            compatibility_projection(&report.compatibility.matrix[0].profiles),
            vec![(
                "github-copilot",
                CompatibilityStatus::Warn,
                vec!["SKILL050"]
            )]
        );
    }

    #[test]
    fn scan_combined_spec_and_github_copilot_keeps_structural_allowed_tools_finding() {
        let workspace = TestWorkspace::new("scan-github-copilot-combined-allowed-tools");
        workspace.write_file(
            ".github/skills/reviewer/SKILL.md",
            r#"---
name: reviewer
description: Reviews repository changes.
allowed-tools:
  - Bash(git diff:*)
---

# Reviewer
"#,
        );
        let config = parse_audit_config(
            r#"
profiles:
  - agent-skills-spec
  - github-copilot
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        let mut rule_ids = report
            .findings
            .iter()
            .map(|finding| finding.rule_id.as_str())
            .collect::<Vec<_>>();
        rule_ids.sort_unstable();
        assert_eq!(rule_ids, vec!["SKILL040", "SKILL050"]);
        assert!(report
            .findings
            .iter()
            .all(|finding| finding.message.contains("`allowed-tools`")));
        assert_eq!(
            compatibility_projection(&report.compatibility.matrix[0].profiles),
            vec![
                (
                    "agent-skills-spec",
                    CompatibilityStatus::Warn,
                    vec!["SKILL040"]
                ),
                (
                    "github-copilot",
                    CompatibilityStatus::Warn,
                    vec!["SKILL050"]
                ),
            ]
        );
    }

    #[test]
    fn scan_github_copilot_warns_for_script_references_without_finding_id() {
        let workspace = TestWorkspace::new("scan-github-copilot-script-warn");
        workspace.write_file(
            ".github/skills/reviewer/SKILL.md",
            r#"---
name: reviewer
description: Reviews repository changes.
---

# Reviewer

Run [check](scripts/check.sh) when explicitly requested.
"#,
        );
        workspace.write_file(".github/skills/reviewer/scripts/check.sh", "echo check\n");
        let config = parse_audit_config(
            r#"
profiles:
  - github-copilot
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert!(report.findings.is_empty());
        assert_eq!(
            compatibility_projection(&report.compatibility.matrix[0].profiles),
            vec![(
                "github-copilot",
                CompatibilityStatus::Warn,
                Vec::<&str>::new()
            )]
        );
    }

    #[test]
    fn scan_github_copilot_fails_for_baseline_required_findings() {
        let workspace = TestWorkspace::new("scan-github-copilot-baseline-fail");
        workspace.write_file(
            ".github/skills/reviewer/SKILL.md",
            r#"---
name: reviewer
---
"#,
        );
        let config = parse_audit_config(
            r#"
profiles:
  - github-copilot
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert_eq!(
            compatibility_projection(&report.compatibility.matrix[0].profiles),
            vec![(
                "github-copilot",
                CompatibilityStatus::Fail,
                vec!["SKILL002"]
            )]
        );
    }

    #[test]
    fn scan_github_copilot_ignores_suppressed_skill050() {
        let workspace = TestWorkspace::new("scan-github-copilot-suppressed-skill050");
        workspace.write_file(
            ".github/skills/reviewer/SKILL.md",
            r#"---
name: reviewer
description: Reviews repository changes.
allowed-tools:
  - Bash(git diff:*)
---
"#,
        );
        let config = parse_audit_config(
            r#"
profiles:
  - github-copilot

ignore:
  - rule: SKILL050
    path: .github/skills/reviewer/SKILL.md
    reason: Repository wrapper translates host-specific tool metadata.
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert_eq!(
            report
                .findings
                .iter()
                .map(|finding| finding.rule_id.as_str())
                .collect::<Vec<_>>(),
            vec!["SKILL040"]
        );
        assert_eq!(report.summary.suppressed_finding_count, 1);
        assert_eq!(
            compatibility_projection(&report.compatibility.matrix[0].profiles),
            vec![(
                "github-copilot",
                CompatibilityStatus::Pass,
                Vec::<&str>::new()
            )]
        );
    }

    #[test]
    fn scan_generic_fails_for_required_baseline_findings() {
        let workspace = TestWorkspace::new("scan-generic-fail");
        workspace.write_file(
            "SKILL.md",
            r#"---
description: Missing name fixture.
owner: platform
---

This manifest intentionally has no heading fallback.
"#,
        );
        let config = parse_audit_config(
            r#"
profiles:
  - generic
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert_eq!(
            compatibility_projection(&report.compatibility.matrix[0].profiles),
            vec![(
                "generic",
                CompatibilityStatus::Fail,
                vec!["SKILL001", "SKILL040"]
            )]
        );
    }

    #[test]
    fn scan_generic_ignores_suppressed_findings() {
        let workspace = TestWorkspace::new("scan-generic-suppressed");
        workspace.write_file(
            "SKILL.md",
            r#"---
description: Suppressed missing name fixture.
---

This manifest intentionally has no heading fallback.
"#,
        );
        let config = parse_audit_config(
            r#"
profiles:
  - generic

ignore:
  - rule: SKILL001
    path: SKILL.md
    reason: Accepted missing name fixture.
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert!(report.findings.is_empty());
        assert_eq!(report.summary.suppressed_finding_count, 1);
        assert_eq!(
            compatibility_projection(&report.compatibility.matrix[0].profiles),
            vec![("generic", CompatibilityStatus::Pass, Vec::<&str>::new())]
        );
    }

    #[test]
    fn scan_agent_skills_spec_ignores_suppressed_findings() {
        let workspace = TestWorkspace::new("scan-agent-spec-suppressed");
        workspace.write_file(
            "SKILL.md",
            r#"---
description: Suppressed missing name fixture.
---

This manifest intentionally has no heading fallback.
"#,
        );
        let config = parse_audit_config(
            r#"
ignore:
  - rule: SKILL001
    path: SKILL.md
    reason: Accepted missing name fixture.
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert!(report.findings.is_empty());
        assert_eq!(report.summary.suppressed_finding_count, 1);
        assert_eq!(
            compatibility_projection(&report.compatibility.matrix[0].profiles)[0],
            (
                "agent-skills-spec",
                CompatibilityStatus::Pass,
                Vec::<&str>::new()
            )
        );
    }

    #[test]
    fn scan_explicit_config_profiles_limit_matrix_and_preserve_order() {
        let workspace = TestWorkspace::new("scan-configured-compatibility");
        workspace.write_file(
            "zeta/SKILL.md",
            r#"---
name: zeta
description: Zeta compatibility fixture.
---

# Zeta
"#,
        );
        workspace.write_file(
            "alpha/SKILL.md",
            r#"---
name: alpha
description: Alpha compatibility fixture.
---

# Alpha
"#,
        );
        let config = parse_audit_config(
            r#"
profiles:
  - generic
  - codex
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert_eq!(report.compatibility.profiles, vec!["generic", "codex"]);
        assert_eq!(
            report
                .compatibility
                .matrix
                .iter()
                .map(|row| (row.path.as_str(), row.name.as_deref()))
                .collect::<Vec<_>>(),
            vec![
                ("alpha/SKILL.md", Some("alpha")),
                ("zeta/SKILL.md", Some("zeta")),
            ]
        );
        for row in &report.compatibility.matrix {
            assert_eq!(
                compatibility_projection(&row.profiles),
                vec![
                    ("generic", CompatibilityStatus::Pass, Vec::<&str>::new()),
                    ("codex", CompatibilityStatus::Warn, Vec::<&str>::new()),
                ]
            );
        }
        assert_eq!(report.summary.finding_count, 0);
        assert_eq!(report.summary.suppressed_finding_count, 0);
    }

    #[test]
    fn scan_explicit_config_profiles_evaluates_agent_spec_when_selected() {
        let workspace = TestWorkspace::new("scan-agent-spec-selected-profile");
        workspace.write_file(
            "SKILL.md",
            r#"---
name: selected-agent-spec
---

# Selected Agent Spec
"#,
        );
        let config = parse_audit_config(
            r#"
profiles:
  - codex
  - agent-skills-spec
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert_eq!(
            compatibility_projection(&report.compatibility.matrix[0].profiles),
            vec![
                ("codex", CompatibilityStatus::Fail, vec!["SKILL002"]),
                (
                    "agent-skills-spec",
                    CompatibilityStatus::Fail,
                    vec!["SKILL002"]
                ),
            ]
        );
    }

    #[test]
    fn scan_explicit_config_profiles_evaluates_generic_when_selected() {
        let workspace = TestWorkspace::new("scan-generic-selected-profile");
        workspace.write_file(
            "SKILL.md",
            r#"---
name: selected-generic
description: Selected generic fixture.
owner: platform
---

# Selected Generic
"#,
        );
        let config = parse_audit_config(
            r#"
profiles:
  - codex
  - generic
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert_eq!(
            compatibility_projection(&report.compatibility.matrix[0].profiles),
            vec![
                ("codex", CompatibilityStatus::Warn, vec!["SKILL040"]),
                ("generic", CompatibilityStatus::Warn, vec!["SKILL040"]),
            ]
        );
    }

    #[test]
    fn scan_ignores_non_relative_file_references() {
        let workspace = TestWorkspace::new("scan-non-relative-references");
        workspace.write_file(
            "SKILL.md",
            r#"---
name: non-relative-references
description: Non-relative reference fixture.
---

# Non Relative References

Use [http](http://example.test), [https](https://example.test),
[mail](mailto:security@example.test), [anchor](#non-relative-references),
and [ftp](ftp://example.test/file), [tel](tel:+15551234567),
[urn](urn:isbn:9780143127796), [vscode](vscode://file/example).
"#,
        );

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");

        assert!(report.packages[0].graph.references.is_empty());
        assert!(report.findings.is_empty());
    }

    #[test]
    fn scan_checks_relative_references_after_stripping_query_and_fragment() {
        let workspace = TestWorkspace::new("scan-reference-query-fragment");
        workspace.write_file(
            "SKILL.md",
            r#"---
name: query-fragment-references
description: Query and fragment reference fixture.
---

# Query Fragment References

Read [guide](references/guide.md?raw=1#setup) and inspect ![badge](assets/badge.png#icon).
"#,
        );
        workspace.write_file("references/guide.md", "# Guide\n");
        workspace.write_file("assets/badge.png", "badge\n");

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");

        assert_eq!(report.summary.broken_reference_count, 0);
        assert_eq!(
            report.packages[0]
                .graph
                .references
                .iter()
                .map(|reference| (reference.target.as_str(), reference.exists))
                .collect::<Vec<_>>(),
            vec![
                ("assets/badge.png#icon", Some(true)),
                ("references/guide.md?raw=1#setup", Some(true)),
            ]
        );
    }

    #[test]
    fn scan_marks_unsafe_filesystem_references_missing_without_escaping_skill_root() {
        let workspace = TestWorkspace::new("scan-unsafe-references");
        workspace.write_file(
            "skill/SKILL.md",
            r#"---
name: unsafe-references
description: Unsafe reference fixture.
---

# Unsafe References

Read [parent](../outside.md), [absolute](/outside.md), and [windows](C:/outside.md).
"#,
        );
        workspace.write_file("outside.md", "# Outside\n");

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");

        assert_eq!(report.summary.broken_reference_count, 3);
        assert_eq!(
            report.packages[0]
                .graph
                .references
                .iter()
                .map(|reference| (reference.target.as_str(), reference.exists))
                .collect::<Vec<_>>(),
            vec![
                ("../outside.md", Some(false)),
                ("/outside.md", Some(false)),
                ("C:/outside.md", Some(false)),
            ]
        );
    }

    #[test]
    fn display_path_returns_original_path_when_not_under_root() {
        let root = Path::new("root");
        let outside = Path::new("outside").join("SKILL.md");

        assert_eq!(display_path(root, &outside), "outside/SKILL.md");
    }

    #[test]
    fn reports_skill001_missing_name_with_complete_finding_metadata() {
        let workspace = TestWorkspace::new("scan-skill001");
        workspace.write_file(
            "SKILL.md",
            r#"---
description: Missing name fixture.
---

This manifest has a description but no frontmatter name or heading fallback.
"#,
        );

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");

        assert_eq!(report.findings.len(), 1);
        assert_finding(
            &report.findings[0],
            ExpectedFinding {
                rule_id: "SKILL001",
                message: "The skill manifest does not declare a name.",
                path: "SKILL.md",
                line: Some(1),
            },
        );
    }

    #[test]
    fn reports_skill002_missing_description_with_complete_finding_metadata() {
        let workspace = TestWorkspace::new("scan-skill002");
        workspace.write_file(
            "SKILL.md",
            r#"---
name: missing-description
---

# Missing Description
"#,
        );

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");

        assert_eq!(report.findings.len(), 1);
        assert_finding(
            &report.findings[0],
            ExpectedFinding {
                rule_id: "SKILL002",
                message: "The skill manifest does not declare a description.",
                path: "SKILL.md",
                line: Some(1),
            },
        );
    }

    #[test]
    fn reports_skill010_broken_relative_reference_with_complete_finding_metadata() {
        let workspace = TestWorkspace::new("scan-skill010");
        workspace.write_file(
            "SKILL.md",
            r#"---
name: broken-reference
description: Broken reference fixture.
---

# Broken Reference

Read [missing guidance](references/missing.md).
"#,
        );

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");

        assert_eq!(report.findings.len(), 1);
        assert_finding(
            &report.findings[0],
            ExpectedFinding {
                rule_id: "SKILL010",
                message:
                    "The manifest references `references/missing.md`, but the file was not found.",
                path: "SKILL.md",
                line: Some(8),
            },
        );
    }

    #[test]
    fn reports_skill020_oversized_manifest_with_complete_finding_metadata() {
        let workspace = TestWorkspace::new("scan-skill020");
        workspace.write_file(
            "SKILL.md",
            r#"---
name: oversized
description: Oversized fixture.
---

# Oversized

This manifest is valid but deliberately longer than the low test threshold.
"#,
        );

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                max_manifest_bytes: 80,
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert_eq!(report.findings.len(), 1);
        assert_finding(
            &report.findings[0],
            ExpectedFinding {
                rule_id: "SKILL020",
                message: "The SKILL.md file exceeds the recommended manifest size.",
                path: "SKILL.md",
                line: Some(1),
            },
        );
    }

    #[test]
    fn reports_skill030_duplicate_names_with_complete_finding_metadata() {
        let workspace = TestWorkspace::new("scan-skill030");
        workspace.write_file(
            "alpha/SKILL.md",
            r#"---
name: shared-name
description: Alpha duplicate fixture.
---

# Alpha
"#,
        );
        workspace.write_file(
            "beta/SKILL.md",
            r#"---
name: shared-name
description: Beta duplicate fixture.
---

# Beta
"#,
        );

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");

        assert_eq!(report.findings.len(), 2);
        assert_eq!(report.summary.package_count, 2);
        assert_eq!(report.summary.finding_count, 2);
        assert_eq!(report.summary.invalid_manifest_count, 0);
        assert_eq!(report.summary.broken_reference_count, 0);
        assert_duplicate_name_finding(
            &report.findings[0],
            "shared-name",
            "alpha/SKILL.md",
            &["beta/SKILL.md"],
        );
        assert_duplicate_name_finding(
            &report.findings[1],
            "shared-name",
            "beta/SKILL.md",
            &["alpha/SKILL.md"],
        );
    }

    #[test]
    fn duplicate_name_findings_are_deterministic_by_package_path() {
        let workspace = TestWorkspace::new("scan-skill030-order");
        workspace.write_file(
            "zeta/SKILL.md",
            r#"---
name: shared-name
description: Zeta duplicate fixture.
---

# Zeta
"#,
        );
        workspace.write_file(
            "alpha/SKILL.md",
            r#"---
name: shared-name
description: Alpha duplicate fixture.
---

# Alpha
"#,
        );
        workspace.write_file(
            "middle/SKILL.md",
            r#"---
name: shared-name
description: Middle duplicate fixture.
---

# Middle
"#,
        );

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");

        assert_eq!(
            report
                .findings
                .iter()
                .map(|finding| finding.location.path.as_str())
                .collect::<Vec<_>>(),
            vec!["alpha/SKILL.md", "middle/SKILL.md", "zeta/SKILL.md"]
        );
        assert_duplicate_name_finding(
            &report.findings[0],
            "shared-name",
            "alpha/SKILL.md",
            &["middle/SKILL.md", "zeta/SKILL.md"],
        );
        assert_duplicate_name_finding(
            &report.findings[1],
            "shared-name",
            "middle/SKILL.md",
            &["alpha/SKILL.md", "zeta/SKILL.md"],
        );
        assert_duplicate_name_finding(
            &report.findings[2],
            "shared-name",
            "zeta/SKILL.md",
            &["alpha/SKILL.md", "middle/SKILL.md"],
        );
    }

    #[test]
    fn missing_name_packages_do_not_participate_in_duplicate_name_detection() {
        let workspace = TestWorkspace::new("scan-skill030-missing-name");
        workspace.write_file(
            "alpha/SKILL.md",
            r#"---
description: Missing name alpha fixture.
---

No heading fallback.
"#,
        );
        workspace.write_file(
            "beta/SKILL.md",
            r#"---
description: Missing name beta fixture.
---

No heading fallback.
"#,
        );

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");

        assert_eq!(report.summary.package_count, 2);
        assert_eq!(report.summary.finding_count, 2);
        assert_eq!(report.summary.invalid_manifest_count, 2);
        assert_eq!(report.summary.broken_reference_count, 0);
        assert!(report
            .findings
            .iter()
            .all(|finding| finding.rule_id == "SKILL001"));
    }

    #[test]
    fn duplicate_name_detection_is_case_sensitive() {
        let workspace = TestWorkspace::new("scan-skill030-case-sensitive");
        workspace.write_file(
            "upper/SKILL.md",
            r#"---
name: Example
description: Uppercase fixture.
---

# Upper
"#,
        );
        workspace.write_file(
            "lower/SKILL.md",
            r#"---
name: example
description: Lowercase fixture.
---

# Lower
"#,
        );

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");

        assert_eq!(report.summary.package_count, 2);
        assert_eq!(report.summary.finding_count, 0);
        assert!(report.findings.is_empty());
    }

    #[test]
    fn reports_skill040_unknown_frontmatter_field_with_complete_finding_metadata() {
        let workspace = TestWorkspace::new("scan-skill040");
        workspace.write_file(
            "SKILL.md",
            r#"---
name: unknown-frontmatter
description: Unknown frontmatter fixture.
experimental_host_hint: codex-only
---

# Unknown Frontmatter
"#,
        );

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");

        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.summary.invalid_manifest_count, 0);
        assert_eq!(report.summary.broken_reference_count, 0);

        let finding = &report.findings[0];
        let metadata = rule_metadata("SKILL040").expect("rule metadata exists");
        assert_eq!(finding.rule_id, "SKILL040");
        assert_eq!(finding.severity, Severity::Low);
        assert_eq!(finding.category, FindingCategory::Compatibility);
        assert_eq!(finding.title, metadata.title);
        assert_eq!(
            finding.message,
            "The manifest declares unsupported frontmatter field `experimental_host_hint`."
        );
        assert_eq!(finding.location.path, "SKILL.md");
        assert_eq!(finding.location.line, Some(4));
        assert_eq!(finding.rationale, metadata.rationale);
        assert_eq!(finding.remediation, metadata.remediation);
        assert_eq!(finding.suppression, metadata.suppression_guidance);
    }

    #[test]
    fn host_specific_frontmatter_still_reports_skill040_not_skill050() {
        let workspace = TestWorkspace::new("scan-host-specific-metadata-skill040");
        workspace.write_file(
            "SKILL.md",
            r#"---
name: host-specific-frontmatter
description: Host-specific frontmatter fixture.
codex:
  tools:
    - shell
---

# Host-specific Frontmatter
"#,
        );

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");

        assert_eq!(
            report
                .findings
                .iter()
                .map(|finding| finding.rule_id.as_str())
                .collect::<Vec<_>>(),
            vec!["SKILL040"]
        );
        assert_eq!(
            report.findings[0].message,
            "The manifest declares unsupported frontmatter field `codex`."
        );
    }

    #[test]
    fn reports_skill040_unknown_frontmatter_field_line_from_crlf_frontmatter() {
        let workspace = TestWorkspace::new("scan-skill040-crlf-frontmatter");
        workspace.write_file(
            "SKILL.md",
            "\u{feff}---\r\nname: crlf-frontmatter\r\ndescription: CRLF frontmatter fixture.\r\nwindows_only_hint: true\r\n---\r\n\r\n# CRLF Frontmatter\r\n",
        );

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");

        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].rule_id, "SKILL040");
        assert_eq!(report.findings[0].location.line, Some(4));
    }

    #[test]
    fn accepted_frontmatter_fields_do_not_report_skill040() {
        let workspace = TestWorkspace::new("scan-skill040-accepted-fields");
        workspace.write_file(
            "SKILL.md",
            r#"---
name: accepted-frontmatter
description: Accepted frontmatter fixture.
tools:
  - shell
permissions:
  - filesystem-read
---

# Accepted Frontmatter
"#,
        );

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");

        assert!(report.findings.is_empty());
        assert_eq!(report.summary.finding_count, 0);
    }

    #[test]
    fn unknown_frontmatter_fields_are_reported_in_stable_order() {
        let workspace = TestWorkspace::new("scan-skill040-stable-order");
        workspace.write_file(
            "SKILL.md",
            r#"---
name: stable-unknown-frontmatter
description: Stable unknown frontmatter fixture.
zeta_hint: last
alpha_hint: first
middle_hint: middle
---

# Stable Unknown Frontmatter
"#,
        );

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");

        assert_eq!(
            report
                .findings
                .iter()
                .map(|finding| finding.message.as_str())
                .collect::<Vec<_>>(),
            vec![
                "The manifest declares unsupported frontmatter field `zeta_hint`.",
                "The manifest declares unsupported frontmatter field `alpha_hint`.",
                "The manifest declares unsupported frontmatter field `middle_hint`.",
            ]
        );
        assert!(report
            .findings
            .iter()
            .all(|finding| finding.rule_id == "SKILL040"));
        assert_eq!(report.summary.invalid_manifest_count, 0);
        assert_eq!(report.summary.broken_reference_count, 0);
    }

    #[test]
    fn scan_reports_missing_name_missing_description_broken_reference_and_size() {
        let workspace = TestWorkspace::new("scan-structural-findings");
        workspace.write_file(
            "a-broken-reference/SKILL.md",
            r#"---
name: broken-reference
description: Broken reference fixture.
---

# Broken Reference

Read [missing](references/missing.md).
"#,
        );
        workspace.write_file(
            "b-missing-name/SKILL.md",
            r#"---
description: Missing name fixture.
---

This starts with a paragraph and has no heading fallback.
"#,
        );
        workspace.write_file(
            "c-missing-description/SKILL.md",
            r#"---
name: missing-description
---

# Missing Description
"#,
        );
        workspace.write_file(
            "d-oversized/SKILL.md",
            r#"---
name: oversized
description: Oversized fixture.
---

# Oversized

This content exceeds the deliberately tiny test threshold.
This extra line keeps only this manifest above the test size limit.
This second extra line makes the intended `SKILL020` case unambiguous.
"#,
        );

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                max_manifest_bytes: 180,
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        let rule_ids = report
            .findings
            .iter()
            .map(|finding| finding.rule_id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            rule_ids,
            vec!["SKILL010", "SKILL001", "SKILL002", "SKILL020"]
        );
        assert_eq!(report.summary.package_count, 4);
        assert_eq!(report.summary.finding_count, 4);
        assert_eq!(report.summary.invalid_manifest_count, 2);
        assert_eq!(report.summary.broken_reference_count, 1);

        let broken_reference = &report.findings[0];
        let metadata = rule_metadata("SKILL010").expect("rule metadata exists");
        assert_eq!(broken_reference.severity, Severity::Low);
        assert_eq!(broken_reference.category, FindingCategory::Spec);
        assert_eq!(broken_reference.title, metadata.title);
        assert!(broken_reference.message.contains("references/missing.md"));
        assert_eq!(
            broken_reference.location.path,
            "a-broken-reference/SKILL.md"
        );
        assert_eq!(broken_reference.rationale, metadata.rationale);
        assert_eq!(broken_reference.remediation, metadata.remediation);
        assert_eq!(broken_reference.suppression, metadata.suppression_guidance);
    }

    #[test]
    fn scan_finding_metadata_matches_rule_registry_for_implemented_rules() {
        let workspace = TestWorkspace::new("scan-rule-metadata");
        workspace.write_file(
            "a-broken-reference/SKILL.md",
            r#"---
name: broken-reference
description: Broken reference fixture.
---

# Broken Reference

Read [missing](references/missing.md).
"#,
        );
        workspace.write_file(
            "b-missing-name/SKILL.md",
            r#"---
description: Missing name fixture.
---

No heading fallback is present here.
"#,
        );
        workspace.write_file(
            "c-missing-description/SKILL.md",
            r#"---
name: missing-description
---

# Missing Description
"#,
        );
        workspace.write_file(
            "d-duplicate-a/SKILL.md",
            r#"---
name: duplicate-name
description: Duplicate fixture A.
---

# Duplicate A
"#,
        );
        workspace.write_file(
            "e-duplicate-b/SKILL.md",
            r#"---
name: duplicate-name
description: Duplicate fixture B.
---

# Duplicate B
"#,
        );
        workspace.write_file(
            "f-unknown-frontmatter/SKILL.md",
            r#"---
name: unknown-frontmatter
description: Unknown frontmatter fixture.
owner: security
---

# Unknown Frontmatter
"#,
        );
        workspace.write_file(
            "g-malformed-frontmatter/SKILL.md",
            r#"---
name: [unterminated
---

# Malformed Frontmatter
"#,
        );
        let mut oversized_manifest = String::from(
            "---\nname: oversized\ndescription: Oversized fixture.\n---\n\n# Oversized\n\n",
        );
        oversized_manifest
            .push_str(&"x".repeat(ScanOptions::default().max_manifest_bytes as usize));
        workspace.write_file("h-oversized/SKILL.md", &oversized_manifest);

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");
        let mut covered_rule_ids = report
            .findings
            .iter()
            .map(|finding| finding.rule_id.as_str())
            .collect::<Vec<_>>();
        covered_rule_ids.sort_unstable();
        covered_rule_ids.dedup();

        assert_eq!(
            covered_rule_ids,
            vec![
                "SKILL001", "SKILL002", "SKILL010", "SKILL020", "SKILL030", "SKILL040", "SKILL041",
            ]
        );
        for finding in &report.findings {
            let metadata =
                rule_metadata(&finding.rule_id).expect("scanner finding must have metadata");

            assert_eq!(finding.title, metadata.title, "{} title", finding.rule_id);
            assert_eq!(
                finding.severity,
                expected_severity(metadata.severity),
                "{} severity",
                finding.rule_id
            );
            assert_eq!(
                finding.category,
                expected_category(metadata.category),
                "{} category",
                finding.rule_id
            );
            assert_eq!(
                finding.rationale, metadata.rationale,
                "{} rationale",
                finding.rule_id
            );
            assert_eq!(
                finding.remediation, metadata.remediation,
                "{} remediation",
                finding.rule_id
            );
            assert_eq!(
                finding.suppression, metadata.suppression_guidance,
                "{} suppression",
                finding.rule_id
            );
        }
    }

    #[test]
    fn scan_sorts_packages_and_findings_deterministically() {
        let workspace = TestWorkspace::new("scan-deterministic-order");
        workspace.write_file("zeta/SKILL.md", "# Zeta\n");
        workspace.write_file("alpha/SKILL.md", "# Alpha\n");
        workspace.write_file("middle/SKILL.md", "# Middle\n");

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");

        assert_eq!(
            report
                .packages
                .iter()
                .map(|package| package.manifest_path.as_str())
                .collect::<Vec<_>>(),
            vec!["alpha/SKILL.md", "middle/SKILL.md", "zeta/SKILL.md"]
        );
        assert_eq!(
            report
                .findings
                .iter()
                .map(finding_sort_tuple)
                .collect::<Vec<_>>(),
            vec![
                (
                    "alpha/SKILL.md",
                    Some(1),
                    "SKILL002",
                    "The skill manifest does not declare a description."
                ),
                (
                    "middle/SKILL.md",
                    Some(1),
                    "SKILL002",
                    "The skill manifest does not declare a description."
                ),
                (
                    "zeta/SKILL.md",
                    Some(1),
                    "SKILL002",
                    "The skill manifest does not declare a description."
                ),
            ]
        );
    }

    #[test]
    fn scan_inventories_artifact_files_recursively_without_top_level_dirs() {
        let workspace = TestWorkspace::new("scan-artifact-files");
        workspace.write_file(
            "SKILL.md",
            r#"---
name: artifact-files
description: Artifact file fixture.
---

# Artifact Files
"#,
        );
        workspace.write_file("scripts/build.ps1", "Write-Output build\n");
        workspace.write_file("scripts/nested/run.sh", "echo run\n");
        workspace.write_file("references/guide.md", "# Guide\n");
        workspace.create_dir("assets/images");

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");
        let files = &report.packages[0].graph.files;

        assert_eq!(
            file_projection(files),
            vec![
                (
                    "assets/images",
                    SkillArtifactKind::Assets,
                    SkillFileKind::Directory,
                    0
                ),
                (
                    "references/guide.md",
                    SkillArtifactKind::References,
                    SkillFileKind::File,
                    8
                ),
                (
                    "scripts/build.ps1",
                    SkillArtifactKind::Scripts,
                    SkillFileKind::File,
                    19
                ),
                (
                    "scripts/nested",
                    SkillArtifactKind::Scripts,
                    SkillFileKind::Directory,
                    0
                ),
                (
                    "scripts/nested/run.sh",
                    SkillArtifactKind::Scripts,
                    SkillFileKind::File,
                    9
                ),
            ]
        );
        assert!(files
            .iter()
            .all(|file| !matches!(file.path.as_str(), "scripts" | "references" | "assets")));
    }

    #[test]
    fn scan_reports_no_artifact_files_when_artifact_dirs_are_absent() {
        let workspace = TestWorkspace::new("scan-no-artifact-dirs");
        workspace.write_file(
            "SKILL.md",
            r#"---
name: no-artifacts
description: No artifact directories fixture.
---

# No Artifacts
"#,
        );

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");

        assert_eq!(report.summary.package_count, 1);
        assert!(report.packages[0].graph.artifacts.is_empty());
        assert!(report.packages[0].graph.files.is_empty());
    }

    #[test]
    fn scan_inventories_only_files_under_skill_package_root() {
        let workspace = TestWorkspace::new("scan-package-root-artifacts");
        workspace.write_file(
            "skill/SKILL.md",
            r#"---
name: package-root-artifacts
description: Package root artifact fixture.
---

# Package Root Artifacts
"#,
        );
        workspace.write_file("skill/scripts/in-package.sh", "echo package\n");
        workspace.write_file("scripts/outside.sh", "echo outside\n");
        workspace.write_file("references/outside.md", "# Outside\n");
        workspace.write_file("assets/outside.txt", "outside\n");

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");

        assert_eq!(report.summary.package_count, 1);
        assert_eq!(report.packages[0].root, "skill");
        assert_eq!(
            report.packages[0].graph.artifacts,
            vec!["scripts".to_owned()]
        );
        assert_eq!(
            file_projection(&report.packages[0].graph.files),
            vec![(
                "scripts/in-package.sh",
                SkillArtifactKind::Scripts,
                SkillFileKind::File,
                13
            )]
        );
    }

    #[test]
    fn scan_phase1_artifact_inventory_fixture_is_stable() {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/spec/phase1/artifact-inventory");
        let fixture_file_size = |relative_path: &str| {
            std::fs::metadata(fixture.join(relative_path))
                .expect("fixture file metadata")
                .len()
        };

        let report = scan_path(&fixture, &ScanOptions::default()).expect("scan path");

        assert_eq!(report.summary.package_count, 1);
        assert_eq!(report.packages[0].root, "");
        assert_eq!(
            report.packages[0].graph.artifacts,
            vec!["scripts", "references", "assets"]
        );
        assert_eq!(
            file_projection(&report.packages[0].graph.files),
            vec![
                (
                    "assets/images",
                    SkillArtifactKind::Assets,
                    SkillFileKind::Directory,
                    0
                ),
                (
                    "assets/images/icon.txt",
                    SkillArtifactKind::Assets,
                    SkillFileKind::File,
                    fixture_file_size("assets/images/icon.txt")
                ),
                (
                    "references/guide.md",
                    SkillArtifactKind::References,
                    SkillFileKind::File,
                    fixture_file_size("references/guide.md")
                ),
                (
                    "references/nested",
                    SkillArtifactKind::References,
                    SkillFileKind::Directory,
                    0
                ),
                (
                    "references/nested/checklist.md",
                    SkillArtifactKind::References,
                    SkillFileKind::File,
                    fixture_file_size("references/nested/checklist.md")
                ),
                (
                    "scripts/build.sh",
                    SkillArtifactKind::Scripts,
                    SkillFileKind::File,
                    fixture_file_size("scripts/build.sh")
                ),
                (
                    "scripts/nested",
                    SkillArtifactKind::Scripts,
                    SkillFileKind::Directory,
                    0
                ),
                (
                    "scripts/nested/prepare.ps1",
                    SkillArtifactKind::Scripts,
                    SkillFileKind::File,
                    fixture_file_size("scripts/nested/prepare.ps1")
                ),
            ]
        );
        assert!(report.packages[0]
            .graph
            .files
            .iter()
            .all(|file| !matches!(file.path.as_str(), "scripts" | "references" | "assets")));
    }

    #[test]
    fn scan_phase1_duplicate_names_fixture_reports_skill030() {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/spec/phase1/duplicate-names");

        let report = scan_path(&fixture, &ScanOptions::default()).expect("scan path");

        assert_eq!(report.summary.package_count, 2);
        assert_eq!(report.summary.finding_count, 2);
        assert_eq!(report.summary.invalid_manifest_count, 0);
        assert_eq!(report.summary.broken_reference_count, 0);
        assert_eq!(
            report
                .findings
                .iter()
                .map(|finding| finding.rule_id.as_str())
                .collect::<Vec<_>>(),
            vec!["SKILL030", "SKILL030"]
        );
        assert_duplicate_name_finding(
            &report.findings[0],
            "phase1-duplicate-name",
            "alpha/SKILL.md",
            &["beta/SKILL.md"],
        );
        assert_duplicate_name_finding(
            &report.findings[1],
            "phase1-duplicate-name",
            "beta/SKILL.md",
            &["alpha/SKILL.md"],
        );
    }

    #[test]
    fn scan_ignores_top_level_artifact_file() {
        let workspace = TestWorkspace::new("scan-artifact-file");
        workspace.write_file(
            "SKILL.md",
            r#"---
name: artifact-file
description: Artifact file fixture.
---

# Artifact File
"#,
        );
        workspace.write_file("scripts", "not an artifact directory\n");

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");

        assert!(report.packages[0].graph.artifacts.is_empty());
        assert!(report.packages[0].graph.files.is_empty());
    }

    #[test]
    fn scan_reports_malformed_frontmatter_without_aborting() {
        let workspace = TestWorkspace::new("scan-malformed-frontmatter");
        workspace.write_file(
            "SKILL.md",
            r#"---
name: [unterminated
---

# Malformed
"#,
        );

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");

        assert_eq!(report.summary.package_count, 1);
        assert_eq!(report.summary.finding_count, 1);
        assert_eq!(report.summary.invalid_manifest_count, 1);
        assert_eq!(report.summary.broken_reference_count, 0);
        assert_eq!(report.packages[0].root, "");
        assert_eq!(report.packages[0].manifest_path, "SKILL.md");
        assert!(report.packages[0].manifest.name.is_none());
        assert!(report.packages[0].manifest.description.is_none());
        assert!(report.packages[0].manifest.frontmatter.is_empty());
        assert!(report.packages[0].manifest.body.is_empty());
        assert!(report.packages[0].manifest.headings.is_empty());
        assert!(report.packages[0].manifest.links.is_empty());
        assert!(report.packages[0].manifest.inline_code.is_empty());
        assert!(report.packages[0].manifest.code_blocks.is_empty());
        assert!(report.packages[0].manifest.declared_tools.is_empty());
        assert!(report.packages[0].manifest.declared_permissions.is_empty());
        assert!(report.packages[0].graph.references.is_empty());
        assert!(report.packages[0].graph.artifacts.is_empty());
        assert!(report.packages[0].graph.files.is_empty());

        let finding = &report.findings[0];
        let metadata = rule_metadata("SKILL041").expect("rule metadata exists");
        assert_eq!(finding.rule_id, "SKILL041");
        assert_eq!(finding.severity, Severity::Low);
        assert_eq!(finding.category, FindingCategory::Spec);
        assert_eq!(finding.title, metadata.title);
        assert!(finding
            .message
            .starts_with("The skill manifest frontmatter could not be parsed:"));
        assert!(finding.message.contains("line"));
        assert_eq!(finding.location.path, "SKILL.md");
        assert_eq!(finding.location.line, Some(3));
        assert_eq!(finding.rationale, metadata.rationale);
        assert_eq!(finding.remediation, metadata.remediation);
        assert_eq!(finding.suppression, metadata.suppression_guidance);
    }

    #[test]
    fn scan_reports_unclosed_frontmatter_as_malformed_frontmatter() {
        let workspace = TestWorkspace::new("scan-unclosed-frontmatter");
        workspace.write_file(
            "SKILL.md",
            "\u{feff}---\r\nname: silently-accepted-before\r\n\r\n# Body Heading\r\n",
        );

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");

        assert_eq!(report.summary.package_count, 1);
        assert_eq!(report.summary.finding_count, 1);
        assert_eq!(report.summary.invalid_manifest_count, 1);
        assert!(report.packages[0].manifest.name.is_none());
        assert!(report.packages[0].manifest.description.is_none());
        assert!(report.packages[0].manifest.headings.is_empty());
        let metadata = rule_metadata("SKILL041").expect("rule metadata exists");
        assert_eq!(report.findings[0].rule_id, "SKILL041");
        assert_eq!(report.findings[0].title, metadata.title);
        assert_eq!(report.findings[0].location.path, "SKILL.md");
        assert_eq!(report.findings[0].location.line, Some(1));
        assert!(report.findings[0].message.contains("unclosed frontmatter"));
    }

    #[test]
    fn scan_phase1_malformed_frontmatter_fixture_reports_skill041() {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/spec/phase1/malformed-frontmatter");

        let report = scan_path(&fixture, &ScanOptions::default()).expect("scan path");

        assert_eq!(report.summary.package_count, 1);
        assert_eq!(report.summary.finding_count, 1);
        assert_eq!(report.summary.invalid_manifest_count, 1);
        assert_eq!(report.summary.broken_reference_count, 0);
        assert_eq!(report.findings[0].rule_id, "SKILL041");
        assert_eq!(report.findings[0].location.path, "SKILL.md");
    }

    #[test]
    fn scan_continues_after_malformed_frontmatter_manifest() {
        let workspace = TestWorkspace::new("scan-continues-after-malformed-frontmatter");
        workspace.write_file(
            "broken/SKILL.md",
            r#"---
name: [unterminated
---

# Broken
"#,
        );
        workspace.write_file(
            "valid/SKILL.md",
            r#"---
name: valid-after-broken
description: Valid manifest after malformed frontmatter.
---

# Valid
"#,
        );

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");

        assert_eq!(report.summary.package_count, 2);
        assert_eq!(report.summary.finding_count, 1);
        assert_eq!(report.summary.invalid_manifest_count, 1);
        assert_eq!(
            report
                .packages
                .iter()
                .map(|package| (
                    package.manifest_path.as_str(),
                    package.manifest.name.as_deref()
                ))
                .collect::<Vec<_>>(),
            vec![
                ("broken/SKILL.md", None),
                ("valid/SKILL.md", Some("valid-after-broken")),
            ]
        );
        assert_eq!(report.findings[0].rule_id, "SKILL041");
        assert_eq!(report.findings[0].location.path, "broken/SKILL.md");
    }

    #[test]
    fn scan_returns_read_error_for_invalid_utf8_manifest() {
        let workspace = TestWorkspace::new("scan-invalid-utf8");
        let path = workspace.root().join("SKILL.md");
        std::fs::write(&path, [0xff, 0xfe, b'\n']).expect("write invalid UTF-8 manifest");

        let error =
            scan_path(workspace.root(), &ScanOptions::default()).expect_err("scan should fail");

        match error {
            AuditError::Read { path, source } => {
                assert!(path.ends_with("SKILL.md"), "unexpected path: {path:?}");
                assert_eq!(source.kind(), ErrorKind::InvalidData);
            }
            _ => panic!("expected read error"),
        }
    }

    #[test]
    fn scan_reports_oversized_manifest_without_reading_invalid_utf8_body() {
        let workspace = TestWorkspace::new("scan-oversized-invalid-utf8");
        let path = workspace.root().join("SKILL.md");
        let mut content = vec![b'a'; 129];
        content.push(0xff);
        std::fs::write(&path, content).expect("write oversized invalid UTF-8 manifest");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                max_manifest_bytes: 128,
                ..ScanOptions::default()
            },
        )
        .expect("oversized manifest should not be fully read");

        assert_eq!(report.summary.package_count, 1);
        assert_eq!(report.summary.finding_count, 1);
        assert_eq!(report.summary.invalid_manifest_count, 0);
        assert_eq!(report.summary.broken_reference_count, 0);
        assert_eq!(report.packages[0].root, "");
        assert_eq!(report.packages[0].manifest_path, "SKILL.md");
        assert!(report.packages[0].manifest.name.is_none());
        assert!(report.packages[0].manifest.description.is_none());
        assert!(report.packages[0].manifest.frontmatter.is_empty());
        assert!(report.packages[0].manifest.body.is_empty());
        assert!(report.packages[0].manifest.headings.is_empty());
        assert!(report.packages[0].graph.references.is_empty());
        assert!(report.packages[0].graph.artifacts.is_empty());
        assert!(report.packages[0].graph.files.is_empty());
        assert_finding(
            &report.findings[0],
            ExpectedFinding {
                rule_id: "SKILL020",
                message: "The SKILL.md file exceeds the recommended manifest size.",
                path: "SKILL.md",
                line: Some(1),
            },
        );
    }

    #[test]
    fn scan_reports_missing_name_and_description_for_nul_byte_manifest() {
        let workspace = TestWorkspace::new("scan-nul-byte-manifest");
        let path = workspace.root().join("SKILL.md");
        std::fs::write(&path, b"```\n\0\0\0\n```\n")
            .expect("write valid UTF-8 manifest with NUL bytes");

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");

        assert_eq!(report.summary.package_count, 1);
        assert_eq!(
            report
                .findings
                .iter()
                .map(|finding| finding.rule_id.as_str())
                .collect::<Vec<_>>(),
            vec!["SKILL001", "SKILL002"]
        );
    }

    #[test]
    fn config_suppression_matches_exact_rule_and_normalized_relative_path() {
        let workspace = TestWorkspace::new("scan-suppression-exact");
        workspace.write_file(
            "nested/SKILL.md",
            r#"---
description: Missing name fixture.
---

This manifest intentionally has no heading fallback.
"#,
        );
        let config = parse_audit_config(
            r#"
ignore:
  - rule: SKILL001
    path: nested\SKILL.md
    reason: Accepted missing name fixture.
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert_eq!(report.summary.finding_count, 0);
        assert_eq!(report.summary.suppressed_finding_count, 1);
        assert!(report.findings.is_empty());
        assert_eq!(report.suppressed_findings.len(), 1);
        assert_eq!(report.suppressed_findings[0].finding.rule_id, "SKILL001");
        assert_eq!(
            report.suppressed_findings[0].finding.location.path,
            "nested/SKILL.md"
        );
        assert_eq!(
            report.suppressed_findings[0].suppression.matched_rule,
            "SKILL001"
        );
        assert_eq!(
            report.suppressed_findings[0].suppression.matched_path,
            "nested/SKILL.md"
        );
        assert_eq!(
            report.suppressed_findings[0].suppression.reason,
            "Accepted missing name fixture."
        );
    }

    #[test]
    fn config_suppression_does_not_match_unmatched_rule_or_path() {
        let workspace = TestWorkspace::new("scan-suppression-unmatched");
        workspace.write_file("SKILL.md", "```\nno manifest metadata\n```\n");
        let config = parse_audit_config(
            r#"
ignore:
  - rule: SKILL002
    path: other/SKILL.md
    reason: Wrong path.
  - rule: SKILL010
    path: SKILL.md
    reason: Wrong rule.
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert_eq!(report.summary.finding_count, 2);
        assert_eq!(report.summary.suppressed_finding_count, 0);
        assert!(report.suppressed_findings.is_empty());
        assert_eq!(
            report
                .findings
                .iter()
                .map(|finding| finding.rule_id.as_str())
                .collect::<Vec<_>>(),
            vec!["SKILL001", "SKILL002"]
        );
    }

    #[test]
    fn config_suppression_requires_exact_path_without_globs() {
        let workspace = TestWorkspace::new("scan-suppression-exact-path-only");
        workspace.write_file(
            "skills/reviewer/SKILL.md",
            r#"---
description: Missing name fixture.
---

This manifest intentionally has no heading fallback.
"#,
        );
        let config = parse_audit_config(
            r#"
ignore:
  - rule: SKILL001
    path: skills/*/SKILL.md
    reason: Glob-like paths must not match.
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert_eq!(report.summary.finding_count, 1);
        assert_eq!(report.summary.suppressed_finding_count, 0);
        assert!(report.suppressed_findings.is_empty());
        assert_eq!(report.findings[0].rule_id, "SKILL001");
        assert_eq!(report.findings[0].location.path, "skills/reviewer/SKILL.md");
    }

    #[test]
    fn config_suppression_requires_exact_rule_id() {
        let workspace = TestWorkspace::new("scan-suppression-exact-rule-only");
        workspace.write_file(
            "SKILL.md",
            r#"---
description: Missing name fixture.
---

This manifest intentionally has no heading fallback.
"#,
        );
        let config = parse_audit_config(
            r#"
ignore:
  - rule: SKILL002
    path: SKILL.md
    reason: Different rule on the same path must not match.
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert_eq!(report.summary.finding_count, 1);
        assert_eq!(report.summary.suppressed_finding_count, 0);
        assert!(report.suppressed_findings.is_empty());
        assert_eq!(report.findings[0].rule_id, "SKILL001");
        assert_eq!(report.findings[0].location.path, "SKILL.md");
    }

    #[test]
    fn config_suppression_leaves_unrelated_findings_unaffected() {
        let workspace = TestWorkspace::new("scan-suppression-unrelated");
        workspace.write_file(
            "SKILL.md",
            r#"---
name: suppression-unrelated
owner: platform
---

# Suppression Unrelated

Read [missing](references/missing.md).
"#,
        );
        let config = parse_audit_config(
            r#"
ignore:
  - rule: SKILL010
    path: SKILL.md
    reason: Broken reference tracked elsewhere.
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert_eq!(report.summary.finding_count, 1);
        assert_eq!(report.summary.suppressed_finding_count, 1);
        assert_eq!(report.summary.broken_reference_count, 0);
        assert_eq!(
            report
                .findings
                .iter()
                .map(|finding| finding.rule_id.as_str())
                .collect::<Vec<_>>(),
            vec!["SKILL040"]
        );
        assert_eq!(report.suppressed_findings[0].finding.rule_id, "SKILL010");
    }

    #[test]
    fn multiple_suppressed_findings_keep_deterministic_finding_order() {
        let workspace = TestWorkspace::new("scan-suppression-multiple-order");
        workspace.write_file("alpha/SKILL.md", "```\nno manifest metadata\n```\n");
        workspace.write_file(
            "beta/SKILL.md",
            r#"---
name: broken-reference
description: Broken reference fixture.
---

# Broken Reference

Read [missing](references/missing.md).
"#,
        );
        let config = parse_audit_config(
            r#"
ignore:
  - rule: SKILL010
    path: beta/SKILL.md
    reason: Broken reference tracked elsewhere.
  - rule: SKILL002
    path: alpha/SKILL.md
    reason: Description intentionally omitted.
  - rule: SKILL001
    path: alpha/SKILL.md
    reason: Name intentionally omitted.
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert!(report.findings.is_empty());
        assert_eq!(report.summary.suppressed_finding_count, 3);
        assert_eq!(
            suppressed_finding_projection(&report.suppressed_findings),
            vec![
                ("alpha/SKILL.md", "SKILL001"),
                ("alpha/SKILL.md", "SKILL002"),
                ("beta/SKILL.md", "SKILL010"),
            ]
        );
    }

    #[test]
    fn summary_counts_exclude_suppressed_findings_in_mixed_reports() {
        let workspace = TestWorkspace::new("scan-suppression-summary-mixed");
        workspace.write_file(
            "SKILL.md",
            r#"[](references/missing.md)
"#,
        );
        let config = parse_audit_config(
            r#"
ignore:
  - rule: SKILL001
    path: SKILL.md
    reason: Name intentionally omitted.
  - rule: SKILL010
    path: SKILL.md
    reason: Broken reference tracked elsewhere.
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert_eq!(report.summary.finding_count, 1);
        assert_eq!(report.summary.suppressed_finding_count, 2);
        assert_eq!(report.summary.invalid_manifest_count, 1);
        assert_eq!(report.summary.broken_reference_count, 0);
        assert_eq!(
            report
                .findings
                .iter()
                .map(|finding| finding.rule_id.as_str())
                .collect::<Vec<_>>(),
            vec!["SKILL002"]
        );
        assert_eq!(
            suppressed_finding_projection(&report.suppressed_findings),
            vec![("SKILL.md", "SKILL001"), ("SKILL.md", "SKILL010")]
        );
    }

    #[test]
    fn duplicate_name_suppression_leaves_sibling_duplicate_finding_active() {
        let workspace = TestWorkspace::new("scan-suppression-duplicate-sibling");
        workspace.write_file(
            "alpha/SKILL.md",
            r#"---
name: shared-duplicate
description: Alpha duplicate fixture.
---

# Alpha Duplicate
"#,
        );
        workspace.write_file(
            "beta/SKILL.md",
            r#"---
name: shared-duplicate
description: Beta duplicate fixture.
---

# Beta Duplicate
"#,
        );
        let config = parse_audit_config(
            r#"
ignore:
  - rule: SKILL030
    path: alpha/SKILL.md
    reason: Alpha duplicate accepted for fixture coverage.
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");

        assert_eq!(report.summary.finding_count, 1);
        assert_eq!(report.summary.suppressed_finding_count, 1);
        assert_duplicate_name_finding(
            &report.findings[0],
            "shared-duplicate",
            "beta/SKILL.md",
            &["alpha/SKILL.md"],
        );
        assert_eq!(
            suppressed_finding_projection(&report.suppressed_findings),
            vec![("alpha/SKILL.md", "SKILL030")]
        );
    }

    #[test]
    fn json_output_includes_suppression_summary_and_details() {
        let workspace = TestWorkspace::new("scan-json-suppression-details");
        workspace.write_file("SKILL.md", "```\nno manifest metadata\n```\n");
        let config = parse_audit_config(
            r#"
ignore:
  - rule: SKILL001
    path: SKILL.md
    reason: Name intentionally omitted in regression fixture.
"#,
        )
        .expect("valid config");

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                config: Some(config),
                ..ScanOptions::default()
            },
        )
        .expect("scan path");
        let (_json, value) = report_json_value(&report);

        assert_eq!(value["summary"]["finding_count"], 1);
        assert_eq!(value["summary"]["suppressed_finding_count"], 1);
        assert_eq!(
            json_string_array(&value["findings"], "rule_id"),
            vec!["SKILL002"]
        );
        assert_eq!(
            value["suppressed_findings"][0]["finding"]["rule_id"],
            "SKILL001"
        );
        assert_eq!(
            value["suppressed_findings"][0]["finding"]["location"]["path"],
            "SKILL.md"
        );
        assert_eq!(
            value["suppressed_findings"][0]["suppression"]["matched_rule"],
            "SKILL001"
        );
        assert_eq!(
            value["suppressed_findings"][0]["suppression"]["matched_path"],
            "SKILL.md"
        );
        assert_eq!(
            value["suppressed_findings"][0]["suppression"]["reason"],
            "Name intentionally omitted in regression fixture."
        );
    }

    #[test]
    fn json_output_keeps_suppressed_findings_order_and_stable_bytes() {
        let workspace = TestWorkspace::new("scan-json-suppression-order-stability");
        workspace.write_file("alpha/SKILL.md", "```\nno manifest metadata\n```\n");
        workspace.write_file(
            "beta/SKILL.md",
            r#"---
name: broken-reference
description: Broken reference fixture.
---

# Broken Reference

Read [missing](references/missing.md).
"#,
        );
        let config = parse_audit_config(
            r#"
ignore:
  - rule: SKILL010
    path: beta/SKILL.md
    reason: Broken reference tracked elsewhere.
  - rule: SKILL001
    path: alpha/SKILL.md
    reason: Name intentionally omitted.
  - rule: SKILL002
    path: alpha/SKILL.md
    reason: Description intentionally omitted.
"#,
        )
        .expect("valid config");
        let options = ScanOptions {
            config: Some(config),
            ..ScanOptions::default()
        };

        let first = scan_path(workspace.root(), &options).expect("first scan");
        let second = scan_path(workspace.root(), &options).expect("second scan");
        let (first_json, first_value) = report_json_value(&first);
        let (second_json, second_value) = report_json_value(&second);

        assert_eq!(first_json.as_bytes(), second_json.as_bytes());
        assert_eq!(first_value, second_value);
        assert_eq!(first_value["summary"]["finding_count"], 0);
        assert_eq!(first_value["summary"]["suppressed_finding_count"], 3);

        let suppressed = first_value["suppressed_findings"]
            .as_array()
            .expect("suppressed findings array");
        assert_eq!(
            suppressed
                .iter()
                .map(|entry| {
                    (
                        entry["finding"]["location"]["path"].as_str().expect("path"),
                        entry["finding"]["rule_id"].as_str().expect("rule id"),
                        entry["suppression"]["reason"].as_str().expect("reason"),
                    )
                })
                .collect::<Vec<_>>(),
            vec![
                ("alpha/SKILL.md", "SKILL001", "Name intentionally omitted."),
                (
                    "alpha/SKILL.md",
                    "SKILL002",
                    "Description intentionally omitted."
                ),
                (
                    "beta/SKILL.md",
                    "SKILL010",
                    "Broken reference tracked elsewhere."
                ),
            ]
        );
    }

    #[test]
    fn scan_phase1_oversized_manifest_fixture_reports_only_skill020() {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/spec/phase1/oversized-manifest");

        let report = scan_path(
            &fixture,
            &ScanOptions {
                max_manifest_bytes: 120,
                ..ScanOptions::default()
            },
        )
        .expect("oversized manifest should still parse");

        assert_eq!(report.summary.package_count, 1);
        assert_eq!(
            report
                .findings
                .iter()
                .map(|finding| finding.rule_id.as_str())
                .collect::<Vec<_>>(),
            vec!["SKILL020"]
        );
    }

    #[test]
    fn json_output_uses_relative_paths_and_stable_summary_fields() {
        let workspace = TestWorkspace::new("scan-json-stability");
        workspace.write_file(
            "skill/SKILL.md",
            r#"---
name: json-stability
description: JSON stability fixture.
---

# JSON Stability
"#,
        );

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");
        let (json, value) = report_json_value(&report);

        assert_eq!(value["summary"]["package_count"], 1);
        assert_eq!(value["summary"]["finding_count"], 0);
        assert_eq!(value["summary"]["invalid_manifest_count"], 0);
        assert_eq!(value["summary"]["broken_reference_count"], 0);
        assert_eq!(value["packages"][0]["root"], "skill");
        assert_eq!(value["packages"][0]["manifest_path"], "skill/SKILL.md");
        assert_eq!(value["packages"][0]["manifest"]["name"], "json-stability");
        assert_eq!(
            value["packages"][0]["manifest"]["description"],
            "JSON stability fixture."
        );
        assert_eq!(
            value["compatibility"]["profiles"],
            serde_json::json!(HOST_PROFILES)
        );
        assert_eq!(
            value["compatibility"]["matrix"][0]["path"],
            "skill/SKILL.md"
        );
        assert_eq!(
            value["compatibility"]["matrix"][0]["profiles"]
                .as_array()
                .expect("compatibility profiles")
                .iter()
                .map(|profile| (
                    profile["profile"].as_str().expect("profile"),
                    profile["status"].as_str().expect("status"),
                    profile["finding_ids"]
                        .as_array()
                        .expect("finding ids")
                        .len(),
                ))
                .collect::<Vec<_>>(),
            vec![
                ("agent-skills-spec", "pass", 0),
                ("claude-code", "warn", 0),
                ("codex", "warn", 0),
                ("github-copilot", "warn", 0),
                ("vscode-copilot", "unknown", 0),
                ("generic", "pass", 0),
            ]
        );
        assert!(!json_contains_workspace_root(&json, workspace.root()));
        assert!(!json.contains("timestamp"));
        assert!(!json.contains("generated_at"));
    }

    #[test]
    fn json_output_matches_full_pretty_expected_report() {
        let workspace = TestWorkspace::new("scan-json-full-expected-report");
        workspace.write_file("SKILL.md", "# Stable Snapshot\n\nStable description.\n");

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");
        let json = serde_json::to_string_pretty(&report).expect("serialize report");

        let expected = r##"{
  "packages": [
    {
      "root": "",
      "manifest_path": "SKILL.md",
      "manifest": {
        "name": "Stable Snapshot",
        "description": "Stable description.",
        "frontmatter": {},
        "body": "# Stable Snapshot\n\nStable description.\n",
        "headings": [
          "Stable Snapshot"
        ],
        "links": [],
        "inline_code": [],
        "code_blocks": [],
        "declared_tools": [],
        "declared_permissions": []
      },
      "graph": {
        "references": [],
        "artifacts": [],
        "files": []
      }
    }
  ],
  "findings": [],
  "suppressed_findings": [],
  "summary": {
    "package_count": 1,
    "finding_count": 0,
    "suppressed_finding_count": 0,
    "invalid_manifest_count": 0,
    "broken_reference_count": 0
  },
  "compatibility": {
    "profiles": [
      "agent-skills-spec",
      "claude-code",
      "codex",
      "github-copilot",
      "vscode-copilot",
      "generic"
    ],
    "matrix": [
      {
        "path": "SKILL.md",
        "name": "Stable Snapshot",
        "profiles": [
          {
            "profile": "agent-skills-spec",
            "status": "pass",
            "finding_ids": []
          },
          {
            "profile": "claude-code",
            "status": "warn",
            "finding_ids": []
          },
          {
            "profile": "codex",
            "status": "warn",
            "finding_ids": []
          },
          {
            "profile": "github-copilot",
            "status": "warn",
            "finding_ids": []
          },
          {
            "profile": "vscode-copilot",
            "status": "unknown",
            "finding_ids": []
          },
          {
            "profile": "generic",
            "status": "pass",
            "finding_ids": []
          }
        ]
      }
    ]
  }
}"##;
        assert_eq!(json, expected);
        assert!(!json_contains_workspace_root(&json, workspace.root()));
    }

    #[test]
    fn json_output_orders_packages_deterministically() {
        let workspace = TestWorkspace::new("scan-json-package-order");
        workspace.write_file(
            ".agents/skills/beta/SKILL.md",
            r#"---
name: beta
description: Beta fixture.
---

# Beta
"#,
        );
        workspace.write_file(
            ".agents/skills/alpha/SKILL.md",
            r#"---
name: alpha
description: Alpha fixture.
---

# Alpha
"#,
        );
        workspace.write_file(
            ".agents/skills/zeta/SKILL.md",
            r#"---
name: zeta
description: Zeta fixture.
---

# Zeta
"#,
        );

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");
        let (_json, value) = report_json_value(&report);

        assert_eq!(value["summary"]["package_count"], 3);
        assert_eq!(value["summary"]["finding_count"], 0);
        assert_eq!(
            json_string_array(&value["packages"], "manifest_path"),
            vec![
                ".agents/skills/alpha/SKILL.md",
                ".agents/skills/beta/SKILL.md",
                ".agents/skills/zeta/SKILL.md",
            ]
        );
    }

    #[test]
    fn json_output_orders_findings_deterministically() {
        let workspace = TestWorkspace::new("scan-json-finding-order");
        workspace.write_file(
            "zeta/SKILL.md",
            r#"---
name: zeta
---

# Zeta
"#,
        );
        workspace.write_file(
            "alpha/SKILL.md",
            r#"---
name: alpha
---

# Alpha
"#,
        );
        workspace.write_file(
            "middle/SKILL.md",
            r#"---
name: middle
---

# Middle
"#,
        );

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");
        let (_json, value) = report_json_value(&report);

        assert_eq!(value["summary"]["package_count"], 3);
        assert_eq!(value["summary"]["finding_count"], 3);
        assert_eq!(value["summary"]["invalid_manifest_count"], 3);
        assert_eq!(value["summary"]["broken_reference_count"], 0);
        assert_eq!(
            value["findings"]
                .as_array()
                .expect("findings array")
                .iter()
                .map(|finding| (
                    finding["location"]["path"].as_str().expect("path"),
                    finding["rule_id"].as_str().expect("rule id"),
                    finding["message"].as_str().expect("message"),
                ))
                .collect::<Vec<_>>(),
            vec![
                (
                    "alpha/SKILL.md",
                    "SKILL002",
                    "The skill manifest does not declare a description."
                ),
                (
                    "middle/SKILL.md",
                    "SKILL002",
                    "The skill manifest does not declare a description."
                ),
                (
                    "zeta/SKILL.md",
                    "SKILL002",
                    "The skill manifest does not declare a description."
                ),
            ]
        );
    }

    #[test]
    fn json_output_preserves_finding_metadata_and_summary_counts() {
        let workspace = TestWorkspace::new("scan-json-finding-metadata");
        workspace.write_file(
            "a-broken-reference/SKILL.md",
            r#"---
name: broken-reference
description: Broken reference fixture.
---

# Broken Reference

Read [missing](references/missing.md).
"#,
        );
        workspace.write_file(
            "b-missing-name/SKILL.md",
            r#"---
description: Missing name fixture.
---

This starts with a paragraph and has no heading fallback.
"#,
        );
        workspace.write_file(
            "c-missing-description/SKILL.md",
            r#"---
name: missing-description
---

# Missing Description
"#,
        );
        workspace.write_file(
            "d-oversized/SKILL.md",
            r#"---
name: oversized
description: Oversized fixture.
---

# Oversized

This content exceeds the deliberately tiny test threshold.
This extra line keeps only this manifest above the test size limit.
This second extra line makes the intended `SKILL020` case unambiguous.
"#,
        );

        let report = scan_path(
            workspace.root(),
            &ScanOptions {
                max_manifest_bytes: 180,
                ..ScanOptions::default()
            },
        )
        .expect("scan path");
        let (_json, value) = report_json_value(&report);

        assert_eq!(value["summary"]["package_count"], 4);
        assert_eq!(value["summary"]["finding_count"], 4);
        assert_eq!(value["summary"]["invalid_manifest_count"], 2);
        assert_eq!(value["summary"]["broken_reference_count"], 1);
        assert_eq!(
            json_string_array(&value["findings"], "rule_id"),
            vec!["SKILL010", "SKILL001", "SKILL002", "SKILL020"]
        );

        let findings = value["findings"].as_array().expect("findings array");
        for finding in findings {
            let object = finding.as_object().expect("finding object");
            for key in [
                "rule_id",
                "severity",
                "category",
                "title",
                "message",
                "location",
                "rationale",
                "remediation",
                "suppression",
            ] {
                assert!(object.contains_key(key), "missing finding key {key}");
            }
            assert_eq!(finding["severity"], "low");
            assert_eq!(finding["category"], "spec");
            assert!(finding["title"].as_str().expect("title").len() > 0);
            assert!(finding["message"].as_str().expect("message").len() > 0);
            assert!(finding["rationale"].as_str().expect("rationale").len() > 0);
            assert!(finding["remediation"].as_str().expect("remediation").len() > 0);
            assert!(finding["suppression"]
                .as_str()
                .expect("suppression")
                .contains(finding["rule_id"].as_str().expect("rule id")));

            let location = finding["location"].as_object().expect("location object");
            assert!(location.contains_key("path"));
            assert!(location.contains_key("line"));
            assert!(finding["location"]["path"]
                .as_str()
                .expect("location path")
                .ends_with("SKILL.md"));
            assert!(finding["location"]["line"].is_number());
        }
        assert_eq!(
            findings
                .iter()
                .map(|finding| finding["location"]["line"].as_u64().expect("line"))
                .collect::<Vec<_>>(),
            vec![8, 1, 1, 1]
        );
    }

    #[test]
    fn json_output_uses_relative_reference_paths_without_local_paths() {
        let workspace = TestWorkspace::new("scan-json-relative-references");
        workspace.write_file(
            "skill/SKILL.md",
            r#"---
name: relative-references
description: Relative references fixture.
---

# Relative References

Read [guidance](references/guidance.md).
"#,
        );
        workspace.write_file("skill/references/guidance.md", "# Guidance\n");
        workspace.create_dir("skill/scripts");
        workspace.create_dir("skill/assets");

        let report = scan_path(workspace.root(), &ScanOptions::default()).expect("scan path");
        let (json, value) = report_json_value(&report);

        assert_eq!(value["summary"]["package_count"], 1);
        assert_eq!(value["summary"]["finding_count"], 0);
        assert_eq!(
            value["packages"][0]["graph"]["references"][0]["target"],
            "references/guidance.md"
        );
        assert_eq!(
            value["packages"][0]["graph"]["references"][0]["exists"],
            true
        );
        assert_eq!(value["packages"][0]["graph"]["references"][0]["line"], 8);
        assert_eq!(
            value["packages"][0]["graph"]["artifacts"]
                .as_array()
                .expect("artifacts array")
                .iter()
                .map(|artifact| artifact.as_str().expect("artifact"))
                .collect::<Vec<_>>(),
            vec!["scripts", "references", "assets"]
        );
        assert!(!json_contains_workspace_root(&json, workspace.root()));
    }

    #[test]
    fn json_output_workspace_root_detector_matches_escaped_windows_paths() {
        let root = Path::new(r"C:\ws\saas\agent_skill_auditor");

        assert!(json_contains_workspace_root(
            r"C:\ws\saas\agent_skill_auditor\skill\SKILL.md",
            root
        ));
        assert!(json_contains_workspace_root(
            "C:/ws/saas/agent_skill_auditor/skill/SKILL.md",
            root
        ));
        assert!(json_contains_workspace_root(
            r#"{"path":"C:\\ws\\saas\\agent_skill_auditor\\skill\\SKILL.md"}"#,
            root
        ));
    }

    struct ExpectedFinding {
        rule_id: &'static str,
        message: &'static str,
        path: &'static str,
        line: Option<usize>,
    }

    fn assert_duplicate_name_finding(
        finding: &SkillFinding,
        name: &str,
        path: &str,
        other_paths: &[&str],
    ) {
        let other_paths = other_paths
            .iter()
            .map(|other_path| format!("`{other_path}`"))
            .collect::<Vec<_>>()
            .join(", ");

        assert_eq!(finding.rule_id, "SKILL030");
        assert_eq!(finding.severity, Severity::Low);
        assert_eq!(finding.category, FindingCategory::Compatibility);
        let metadata = rule_metadata("SKILL030").expect("rule metadata exists");

        assert_eq!(finding.title, metadata.title);
        assert_eq!(
            finding.message,
            format!(
                "The skill name `{name}` is also declared by other manifest path(s): {other_paths}."
            )
        );
        assert_eq!(finding.location.path, path);
        assert_eq!(finding.location.line, Some(1));
        assert_eq!(finding.rationale, metadata.rationale);
        assert_eq!(finding.remediation, metadata.remediation);
        assert_eq!(finding.suppression, metadata.suppression_guidance);
    }

    fn assert_finding(finding: &SkillFinding, expected: ExpectedFinding) {
        let metadata = rule_metadata(expected.rule_id).expect("rule metadata exists");

        assert_eq!(finding.rule_id, expected.rule_id);
        assert_eq!(finding.severity, Severity::Low);
        assert_eq!(finding.category, FindingCategory::Spec);
        assert_eq!(finding.title, metadata.title);
        assert_eq!(finding.message, expected.message);
        assert_eq!(finding.location.path, expected.path);
        assert_eq!(finding.location.line, expected.line);
        assert_eq!(finding.rationale, metadata.rationale);
        assert_eq!(finding.remediation, metadata.remediation);
        assert_eq!(finding.suppression, metadata.suppression_guidance);
    }

    fn finding_sort_tuple(finding: &SkillFinding) -> (&str, Option<usize>, &str, &str) {
        (
            finding.location.path.as_str(),
            finding.location.line,
            finding.rule_id.as_str(),
            finding.message.as_str(),
        )
    }

    fn expected_severity(severity: RegistrySeverity) -> Severity {
        match severity {
            RegistrySeverity::Info => Severity::Info,
            RegistrySeverity::Low => Severity::Low,
            RegistrySeverity::Medium => Severity::Medium,
            RegistrySeverity::High => Severity::High,
            RegistrySeverity::Critical => Severity::Critical,
        }
    }

    fn expected_category(category: RegistryCategory) -> FindingCategory {
        match category {
            RegistryCategory::Spec => FindingCategory::Spec,
            RegistryCategory::Compatibility => FindingCategory::Compatibility,
            RegistryCategory::Security => FindingCategory::Security,
            RegistryCategory::Quality => FindingCategory::Quality,
            RegistryCategory::Portability => FindingCategory::Portability,
            RegistryCategory::Reproducibility => FindingCategory::Reproducibility,
        }
    }

    fn file_projection(files: &[SkillFile]) -> Vec<(&str, SkillArtifactKind, SkillFileKind, u64)> {
        files
            .iter()
            .map(|file| {
                (
                    file.path.as_str(),
                    file.artifact,
                    file.kind,
                    file.size_bytes,
                )
            })
            .collect()
    }

    fn compatibility_projection(
        profiles: &[agent_audit_hosts::ProfileCompatibilityResult],
    ) -> Vec<(&str, CompatibilityStatus, Vec<&str>)> {
        profiles
            .iter()
            .map(|profile| {
                (
                    profile.profile.as_str(),
                    profile.status,
                    profile
                        .finding_ids
                        .iter()
                        .map(String::as_str)
                        .collect::<Vec<_>>(),
                )
            })
            .collect()
    }

    fn string_vec(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    fn report_json_value(report: &ScanReport) -> (String, serde_json::Value) {
        let json = serde_json::to_string_pretty(report).expect("serialize report");
        let value = serde_json::from_str(&json).expect("parse report JSON");
        (json, value)
    }

    fn json_string_array(value: &serde_json::Value, key: &str) -> Vec<String> {
        value
            .as_array()
            .expect("JSON array")
            .iter()
            .map(|item| item[key].as_str().expect("string field").to_owned())
            .collect()
    }

    fn suppressed_finding_projection(findings: &[SuppressedFinding]) -> Vec<(&str, &str)> {
        findings
            .iter()
            .map(|entry| {
                (
                    entry.finding.location.path.as_str(),
                    entry.finding.rule_id.as_str(),
                )
            })
            .collect()
    }

    fn json_contains_workspace_root(json: &str, root: &Path) -> bool {
        let raw_root = root.to_string_lossy().into_owned();
        let normalized_root = raw_root.replace('\\', "/");

        for candidate in [raw_root.as_str(), normalized_root.as_str()] {
            if !candidate.is_empty()
                && (json.contains(candidate) || json.contains(&json_escaped_fragment(candidate)))
            {
                return true;
            }
        }

        false
    }

    fn json_escaped_fragment(value: &str) -> String {
        let escaped = serde_json::to_string(value).expect("escape JSON string");
        escaped
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
            .unwrap_or(&escaped)
            .to_owned()
    }
}
