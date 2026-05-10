// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use crate::model::{FindingCategory, FindingLocation, Severity, SkillFinding};
use agent_audit_rules::{
    rule_metadata, RuleCategory as RegistryCategory, RuleMetadata, RuleSeverity as RegistrySeverity,
};

/// Portable frontmatter fields accepted by the initial structural scanner.
const ACCEPTED_FRONTMATTER_FIELDS: &[&str] = &["name", "description", "tools", "permissions"];

#[derive(Debug, Clone)]
pub(crate) struct PackageFacts {
    pub(crate) manifest_path: String,
    pub(crate) manifest: ManifestFacts,
}

#[derive(Debug, Clone)]
pub(crate) enum ManifestFacts {
    Parsed(ParsedManifestFacts),
    UnreadOversized,
    MalformedFrontmatter(MalformedFrontmatterFact),
}

#[derive(Debug, Clone)]
pub(crate) struct ParsedManifestFacts {
    pub(crate) name: Option<String>,
    pub(crate) description: Option<String>,
    pub(crate) frontmatter_fields: Vec<FrontmatterFieldFact>,
    pub(crate) references: Vec<ReferenceFact>,
    pub(crate) oversized: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct FrontmatterFieldFact {
    pub(crate) name: String,
    pub(crate) line: Option<usize>,
}

#[derive(Debug, Clone)]
pub(crate) struct ReferenceFact {
    pub(crate) target: String,
    pub(crate) line: Option<usize>,
    pub(crate) exists: Option<bool>,
}

#[derive(Debug, Clone)]
pub(crate) struct MalformedFrontmatterFact {
    pub(crate) line: Option<usize>,
    pub(crate) parse_message: String,
}

pub(crate) fn evaluate_structural_rules(packages: &[PackageFacts]) -> Vec<SkillFinding> {
    let mut findings = Vec::new();

    for package in packages {
        match &package.manifest {
            ManifestFacts::Parsed(manifest) => {
                evaluate_parsed_manifest(package, manifest, &mut findings);
            }
            ManifestFacts::UnreadOversized => {
                findings.push(oversized_manifest_finding(&package.manifest_path));
            }
            ManifestFacts::MalformedFrontmatter(failure) => {
                findings.push(malformed_frontmatter_finding(
                    &package.manifest_path,
                    failure.line,
                    &failure.parse_message,
                ));
            }
        }
    }

    findings.extend(duplicate_skill_name_findings(packages));
    sort_findings(&mut findings);
    findings
}

fn evaluate_parsed_manifest(
    package: &PackageFacts,
    manifest: &ParsedManifestFacts,
    findings: &mut Vec<SkillFinding>,
) {
    if manifest.name.is_none() {
        findings.push(structural_finding(
            "SKILL001",
            "The skill manifest does not declare a name.",
            &package.manifest_path,
            Some(1),
        ));
    }
    if manifest.description.is_none() {
        findings.push(structural_finding(
            "SKILL002",
            "The skill manifest does not declare a description.",
            &package.manifest_path,
            Some(1),
        ));
    }
    if manifest.oversized {
        findings.push(oversized_manifest_finding(&package.manifest_path));
    }

    for field in manifest
        .frontmatter_fields
        .iter()
        .filter(|field| !ACCEPTED_FRONTMATTER_FIELDS.contains(&field.name.as_str()))
    {
        findings.push(unknown_frontmatter_field_finding(
            &field.name,
            &package.manifest_path,
            field.line.or(Some(1)),
        ));
    }

    for reference in manifest
        .references
        .iter()
        .filter(|reference| reference.exists == Some(false))
    {
        findings.push(structural_finding(
            "SKILL010",
            &format!(
                "The manifest references `{}`, but the file was not found.",
                reference.target
            ),
            &package.manifest_path,
            reference.line,
        ));
    }
}

fn sort_findings(findings: &mut [SkillFinding]) {
    findings.sort_by(|left, right| {
        left.location
            .path
            .cmp(&right.location.path)
            .then(left.location.line.cmp(&right.location.line))
            .then(left.rule_id.cmp(&right.rule_id))
            .then(left.message.cmp(&right.message))
    });
}

fn oversized_manifest_finding(path: &str) -> SkillFinding {
    structural_finding(
        "SKILL020",
        "The SKILL.md file exceeds the recommended manifest size.",
        path,
        Some(1),
    )
}

fn malformed_frontmatter_finding(
    path: &str,
    line: Option<usize>,
    parse_message: &str,
) -> SkillFinding {
    structural_finding(
        "SKILL041",
        &format!("The skill manifest frontmatter could not be parsed: {parse_message}."),
        path,
        line.or(Some(1)),
    )
}

fn structural_finding(
    rule_id: &str,
    message: &str,
    path: &str,
    line: Option<usize>,
) -> SkillFinding {
    let metadata = scanner_rule_metadata(rule_id);
    finding_from_metadata(metadata, message, path, line)
}

fn scanner_rule_metadata(rule_id: &str) -> &'static RuleMetadata {
    rule_metadata(rule_id).expect("implemented scanner rule must have registry metadata")
}

fn finding_from_metadata(
    metadata: &RuleMetadata,
    message: &str,
    path: &str,
    line: Option<usize>,
) -> SkillFinding {
    SkillFinding {
        rule_id: metadata.id.as_str().to_owned(),
        severity: severity_from_metadata(metadata.severity),
        category: category_from_metadata(metadata.category),
        title: metadata.title.to_owned(),
        message: message.to_owned(),
        location: FindingLocation {
            path: path.to_owned(),
            line,
        },
        rationale: metadata.rationale.to_owned(),
        remediation: metadata.remediation.to_owned(),
        suppression: metadata.suppression_guidance.to_owned(),
    }
}

fn severity_from_metadata(severity: RegistrySeverity) -> Severity {
    match severity {
        RegistrySeverity::Info => Severity::Info,
        RegistrySeverity::Low => Severity::Low,
        RegistrySeverity::Medium => Severity::Medium,
        RegistrySeverity::High => Severity::High,
        RegistrySeverity::Critical => Severity::Critical,
    }
}

fn category_from_metadata(category: RegistryCategory) -> FindingCategory {
    match category {
        RegistryCategory::Spec => FindingCategory::Spec,
        RegistryCategory::Compatibility => FindingCategory::Compatibility,
        RegistryCategory::Security => FindingCategory::Security,
        RegistryCategory::Quality => FindingCategory::Quality,
        RegistryCategory::Portability => FindingCategory::Portability,
        RegistryCategory::Reproducibility => FindingCategory::Reproducibility,
    }
}

fn duplicate_skill_name_findings(packages: &[PackageFacts]) -> Vec<SkillFinding> {
    let mut manifest_paths_by_name = BTreeMap::<&str, Vec<&str>>::new();

    for package in packages {
        let ManifestFacts::Parsed(manifest) = &package.manifest else {
            continue;
        };
        if let Some(name) = manifest.name.as_deref() {
            manifest_paths_by_name
                .entry(name)
                .or_default()
                .push(package.manifest_path.as_str());
        }
    }

    let mut findings = Vec::new();
    for (name, manifest_paths) in manifest_paths_by_name
        .iter_mut()
        .filter(|(_, manifest_paths)| manifest_paths.len() > 1)
    {
        manifest_paths.sort_unstable();

        for manifest_path in manifest_paths.iter().copied() {
            let other_paths = manifest_paths
                .iter()
                .copied()
                .filter(|other_path| *other_path != manifest_path)
                .map(|other_path| format!("`{other_path}`"))
                .collect::<Vec<_>>()
                .join(", ");

            findings.push(finding_from_metadata(
                scanner_rule_metadata("SKILL030"),
                &format!(
                    "The skill name `{name}` is also declared by other manifest path(s): {other_paths}."
                ),
                manifest_path,
                Some(1),
            ));
        }
    }

    findings
}

fn unknown_frontmatter_field_finding(field: &str, path: &str, line: Option<usize>) -> SkillFinding {
    finding_from_metadata(
        scanner_rule_metadata("SKILL040"),
        &format!("The manifest declares unsupported frontmatter field `{field}`."),
        path,
        line,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evaluator_reports_parsed_manifest_structural_findings_without_filesystem() {
        let packages = vec![PackageFacts {
            manifest_path: "skill/SKILL.md".to_owned(),
            manifest: ManifestFacts::Parsed(ParsedManifestFacts {
                name: None,
                description: None,
                frontmatter_fields: vec![FrontmatterFieldFact {
                    name: "owner".to_owned(),
                    line: Some(3),
                }],
                references: vec![ReferenceFact {
                    target: "references/missing.md".to_owned(),
                    line: Some(7),
                    exists: Some(false),
                }],
                oversized: true,
            }),
        }];

        let findings = evaluate_structural_rules(&packages);

        assert_eq!(
            finding_projection(&findings),
            vec![
                ("SKILL001", "skill/SKILL.md", Some(1)),
                ("SKILL002", "skill/SKILL.md", Some(1)),
                ("SKILL020", "skill/SKILL.md", Some(1)),
                ("SKILL040", "skill/SKILL.md", Some(3)),
                ("SKILL010", "skill/SKILL.md", Some(7)),
            ]
        );
        assert!(findings[3].message.contains("`owner`"));
        assert!(findings[4].message.contains("references/missing.md"));
    }

    #[test]
    fn evaluator_reports_only_size_for_unread_oversized_manifest() {
        let packages = vec![PackageFacts {
            manifest_path: "SKILL.md".to_owned(),
            manifest: ManifestFacts::UnreadOversized,
        }];

        let findings = evaluate_structural_rules(&packages);

        assert_eq!(
            finding_projection(&findings),
            vec![("SKILL020", "SKILL.md", Some(1))]
        );
    }

    #[test]
    fn evaluator_reports_only_parse_failure_for_malformed_frontmatter() {
        let packages = vec![PackageFacts {
            manifest_path: "SKILL.md".to_owned(),
            manifest: ManifestFacts::MalformedFrontmatter(MalformedFrontmatterFact {
                line: Some(3),
                parse_message: "invalid YAML at line 3".to_owned(),
            }),
        }];

        let findings = evaluate_structural_rules(&packages);

        assert_eq!(
            finding_projection(&findings),
            vec![("SKILL041", "SKILL.md", Some(3))]
        );
        assert_eq!(
            findings[0].message,
            "The skill manifest frontmatter could not be parsed: invalid YAML at line 3."
        );
    }

    #[test]
    fn evaluator_reports_duplicate_names_in_stable_path_order() {
        let packages = vec![
            parsed_package("b/SKILL.md", Some("duplicate")),
            parsed_package("a/SKILL.md", Some("duplicate")),
            parsed_package("c/SKILL.md", Some("unique")),
        ];

        let findings = evaluate_structural_rules(&packages);

        assert_eq!(
            finding_projection(&findings),
            vec![
                ("SKILL030", "a/SKILL.md", Some(1)),
                ("SKILL030", "b/SKILL.md", Some(1)),
            ]
        );
        assert!(findings[0].message.contains("`b/SKILL.md`"));
        assert!(findings[1].message.contains("`a/SKILL.md`"));
    }

    fn parsed_package(path: &str, name: Option<&str>) -> PackageFacts {
        PackageFacts {
            manifest_path: path.to_owned(),
            manifest: ManifestFacts::Parsed(ParsedManifestFacts {
                name: name.map(str::to_owned),
                description: Some("Description.".to_owned()),
                frontmatter_fields: Vec::new(),
                references: Vec::new(),
                oversized: false,
            }),
        }
    }

    fn finding_projection(findings: &[SkillFinding]) -> Vec<(&str, &str, Option<usize>)> {
        findings
            .iter()
            .map(|finding| {
                (
                    finding.rule_id.as_str(),
                    finding.location.path.as_str(),
                    finding.location.line,
                )
            })
            .collect()
    }
}
